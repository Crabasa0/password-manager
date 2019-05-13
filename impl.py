#
#
#   The implementations. All crypto details go here. Called by interface
#
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

import secrets
from os.path import isfile
import datetime
import string
import json

#Constants
ver_salt = '12345678'
enc_salt = '90abcdef'
mac_salt = 'qwertyui'

VERIFICATION_HASH_URL = 'verification-hash'

RAND_PW_SIZE = 14

DIRECTORY_URL = 'directory'
PFILE_URL = 'pfile'
PFILE_NONCE_URL = 'pfile-nonce'
PFILE_MAC_URL = 'pfile-mac'

MAC_LENGTH = 32

#lateinits
mac_key:bytes = None
enc_key:bytes = None
login_time = None
acct_directory:list = None

#login
#potential security improvements:
#   1. Move these functions into interface to reduce password copies on stack
#   alternatively, call functions that write over stack afterwards
#   (Scratch that, CPython only allocates on heap. Wonderful.)
#   2. Generate salts when master password is created/changed
#   3. Check login validity on a separate thread that waits

def check_login_valid():
    td = datetime.datetime.now()
    sess_len = td.seconds #is this checking the seconds timestamp or the length of the session in seconds? It seems like the former. If so, how is this helpful?
    return sess_len > 0 and sess_len < 300

def verify_password(p):
    ver_key = PBKDF2(p, ver_salt, count=10000)
    vhash_file = open(VERIFICATION_HASH_URL, 'rb')
    vhash = vhash_file.read()
    return ver_key == vhash

def derive_enc_key(p):
    global enc_key
    global mac_key
    enc_key = PBKDF2(p, enc_salt, count=10000)
    mac_key = PBKDF2(p, mac_salt, count=10000)
    set_login_time()

def set_login_time():
    global login_time
    login_time = datetime.datetime.now()

#setup
#May be an opportune time to create data files, otherwise we can
#(probably) do it lazily
def setup(p):
    ver_key = PBKDF2(p, ver_salt, count=10000)
    vhash_file = open(VERIFICATION_HASH_URL, 'wb+')
    vhash_file.write(ver_key)
    vhash_file.close()

def check_good_pw(p):
    good_len = len(p) >= 10
    good_uc = any(char in string.ascii_uppercase for char in p)
    good_lc = any(char in string.ascii_lowercase for char in p)
    good_sc = any(char in string.punctuation + ' ' for char in p)
    good_num = any(char in string.digits for char in p)
    return good_len and good_uc and good_lc and good_sc and good_num


#registering an account
def register_acct(name, url, username, password):
    global acct_directory
    global enc_key
    global mac_key

    if not acct_directory:
        load_directory()
    index = get_pfile_len()
    new_entry = {"Name":name, "URL":url, "Username":username, "PW_index":index}
    add_pw_to_pfile(password)
    acct_directory.append(new_entry)

    plaintext = pad(json.dumps(acct_directory).encode('utf-8'), AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(iv)
    mac.update(ciphertext)
    mac = mac.digest()

    enc_accounts = iv + ciphertext + mac
    dir_file = open(DIRECTORY_URL, 'wb+')
    dir_file.write(enc_accounts)
    dir_file.close()

    pass


def get_random_pw():
    char_source = string.ascii_letters + ' ' + string.digits + string.punctuation
    pw_char_list = ['0']*RAND_PW_SIZE   #init at the correct size to prevent copies
    for i in range(RAND_PW_SIZE):
        pw_char_list[i] = secrets.choice(char_source)
    rand_pw = ''.join(pw_char_list)

    #memory 'safety'
    for c in pw_char_list:
        c = '0'

	#DEBUGGING. BE CAREFUL. REMOVE THIS
    print('[DEBUG] Random password was: ' + rand_pw)
    return rand_pw


#Decrypt, load directory file
def load_directory():
    global acct_directory

    if not isfile(DIRECTORY_URL):
        print('No directory file, creating empty list')
        acct_directory = []
        return

    print('Found directory file, decrypting...')
    ifile = open(DIRECTORY_URL, 'rb')
    ciphertext = ifile.read()
    ifile.close()

    # read the encrypted iv, ciphertext, MAC from file
    iv = ciphertext[:AES.block_size]
    mac = ciphertext[-MAC_LENGTH:]
    ciphertext = ciphertext[AES.block_size:-MAC_LENGTH]

    #verify the MAC (could be moved to login, but not necessary)
    MAC = HMAC.new(mac_key, digestmod=SHA256)
    MAC.update(iv)
    MAC.update(ciphertext)
    comp_mac = MAC.digest()
    if comp_mac != mac:
        print('MAC verification failed')
        exit()

    #decrypt the data
    ENC = AES.new(enc_key, AES.MODE_CBC, iv=iv)
    decrypted = ENC.decrypt(ciphertext)
    decrypted = unpad(decrypted, AES.block_size)

    #load the list
    acct_directory = json.loads(decrypted)

def add_pw_to_pfile(password): #SHOULD BE CHECKED
    #convert password string to bytes for encryption
    pb = bytes(password, 'utf-8')
    #pad to create password block(s)
    pb_padded = pad(pb, AES.block_size)
    #encrypt the block(s)
    index = get_pfile_len()
    new_ct = selective_encrypt(pb_padded, index)
    #append the encrypted block to the password file
    pfile = open(PFILE_URL, 'ab+')
    pfile.write(new_ct)
    pfile.close()
    pass
    #do we want to have a MAC here?

#returns the length of the password file in AES blocks
def get_pfile_len():
    if not isfile(PFILE_URL):
        return 0
    else:
        pfile = open(PFILE_URL, 'rb')
        pfile_ct = pfile.read()
        pfile.close()
        return int(len(pfile_ct)/AES.block_size)


def selective_encrypt(data, index): #Finished, i think
    nonce = retrieve_nonce()
    ENC = AES.new(enc_key, AES.MODE_CTR, nonce=nonce, initial_value=index)#check that this works as intended
    encrypted = ENC.encrypt(data)
    return encrypted


def retrieve_nonce():
#do we want to store the nonce as plaintext?
    if not isfile(PFILE_NONCE_URL):
        nonce = get_random_bytes(8)
        nfile = open(PFILE_NONCE_URL, 'wb+')
        nfile.write(nonce)
        nfile.close()
        return nonce
    else:
        nfile = open(PFILE_NONCE_URL, 'rb')
        nonce = nfile.read()
        nfile.close()
        return nonce


def print_accts():
    global acct_directory

    if not acct_directory:
        load_directory()
    for i in range(0,len(acct_directory)):
        print ('Service: ', acct_directory[i]['Name'])
        print ('URL: ', acct_directory[i]['URL'])
        print ('Username: ', acct_directory[i]['Username'])


def search_by_service_name(name):
    global acct_directory

    if not acct_directory:
        load_directory()
    pass


def search_by_url(url):
    global acct_directory

    if not acct_directory:
        load_directory()
    pass


def search_by_username(username):
    global acct_directory

    if not acct_directory:
        load_directory()
    pass

def change_master_pw(new_pw):
    global enc_key
    global mac_key
    global ver_key

    new_enc_key = PBKDF2(new_pw, enc_salt, count=10000)
    new_mac_key = PBKDF2(new_pw, mac_salt, count=10000)
    new_ver_key = PBKDF2(new_pw, ver_salt, count=10000)
    new_pfile_nonce = get_random_bytes(8)
    new_directory_iv = get_random_bytes(AES.block_size)

    #early exit: empty directory (no passwords)
    if acct_directory == []:
        vh_file = open(VERIFICATION_HASH_URL, 'wb')
        vh_file.write(new_ver_key)
        vh_file.close()

        enc_key = new_enc_key
        mac_key = new_mac_key
        ver_key = new_ver_key
        return

    #re-encrypt the files with new info
    #DIRECTORY
    ENC = AES.new(new_enc_key, AES.MODE_CBC, iv=new_directory_iv)
    json_string = json.dumps(acct_directory)
    padded = pad(bytes(json_string, 'utf-8'), AES.block_size)
    encrypted = ENC.encrypt(padded)

    MAC = HMAC.new(new_mac_key, digestmod=SHA256)         # create a HMAC object, pass the right key and specify SHA256 as the hash fn
    MAC.update(new_directory_iv)
    MAC.update(encrypted)
    comp_mac = MAC.digest()    # compute the final HMAC value

    dir_file = open(DIRECTORY_URL, 'wb')
    dir_file.write(new_directory_iv)
    dir_file.write(encrypted)
    dir_file.write(comp_mac)
    dir_file.close()

    #PFILE (securty optimization: do one at a time rather than all at once)
    DEC = AES.new(enc_key, AES.MODE_CTR, nonce=retrieve_nonce(), initial_value=0)
    pfile = open(PFILE_URL, 'rb')
    pfile_ct = pfile.read()
    pfile.close()
    decrypted_pfile = DEC.decrypt(pfile_ct)
    ENC = AES.new(new_enc_key, AES.MODE_CTR, nonce=new_pfile_nonce, initial_value=0)
    reencrypted_pfile = ENC.encrypt(decrypted_pfile)
    pfile = open(PFILE_URL, 'wb')
    pfile.write(reencrypted_pfile)
    pfile.close()

    pfile_nonce_file = open(PFILE_NONCE_URL, 'wb')
    pfile_nonce_file.write(new_pfile_nonce)
    pfile_nonce_file.close()

    #should probably be putting a MAC on the pfile
    pfile_mac_file = open(PFILE_MAC_URL, 'wb')
    PF_MAC = HMAC.new(new_mac_key, digestmod=SHA256)
    PF_MAC.update(new_pfile_nonce)
    PF_MAC.update(reencrypted_pfile)
    pfile_mac_file.write(PF_MAC.digest())
    pfile_mac_file.close()

    #VERIFICATION HASH
    vh_file = open(VERIFICATION_HASH_URL, 'wb')
    vh_file.write(new_ver_key)
    vh_file.close()



    #update the keys in use

    enc_key = new_enc_key
    mac_key = new_mac_key
    ver_key = new_ver_key



pass
