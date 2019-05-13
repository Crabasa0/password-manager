#
#
#   The implementations. All crypto details go here. Called by interface
#
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from threading import Thread
import secrets
from os.path import isfile
import datetime
import time
import string
import json
import pyperclip
import getpass

#Constants
ver_salt = '12345678'
enc_salt = '90abcdef'
mac_salt = 'qwertyui'

VERIFICATION_HASH_URL = 'verification-hash'

DIRECTORY_URL = 'directory'
PFILE_URL = 'pfile'
PFILE_NONCE_URL = 'pfile-nonce'
PFILE_MAC_URL = 'pfile-mac'

RAND_PW_SIZE = 14
MAC_LENGTH = 32

#lateinits
mac_key:bytes = None
enc_key:bytes = None
login_time = None
acct_directory:list = None

#login
def check_login_valid():
    td = datetime.datetime.now() - login_time
    sess_len = td.seconds
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
def setup(p):
    ver_key = PBKDF2(p, ver_salt, count=10000)
    vhash_file = open(VERIFICATION_HASH_URL, 'wb+')
    vhash_file.write(ver_key)
    vhash_file.close()
    derive_enc_key(p)
    set_login_time()

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

    if not acct_directory:
        load_directory()
    index = get_pfile_len()
    new_entry = {"Name":name, "URL":url, "Username":username, "PW_index":index}
    add_pw_to_pfile(password)
    acct_directory.append(new_entry)

    write_acct_info_file()


#encrypt the accounts in the directory and write the result to
#the directory file
def write_acct_info_file():
    global acct_directory
    global enc_key
    global mac_key

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


def get_random_pw():
    char_source = string.ascii_letters + ' ' + string.digits + string.punctuation
    pw_char_list = ['0']*RAND_PW_SIZE   #init at the correct size to prevent copies
    for i in range(RAND_PW_SIZE):
        pw_char_list[i] = secrets.choice(char_source)
    rand_pw = ''.join(pw_char_list)

    #memory 'safety'
    for c in pw_char_list:
        c = '0'

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

    # read the iv, ciphertext, MAC from file
    iv = ciphertext[:AES.block_size]
    mac = ciphertext[-MAC_LENGTH:]
    ciphertext = ciphertext[AES.block_size:-MAC_LENGTH]
    print(ciphertext)

    #verify the MAC
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
    print(decrypted)

    #load the list
    acct_directory = json.loads(decrypted)

def add_pw_to_pfile(password):
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
    #do we want to have a MAC here? We update on logout but it might be good here

    
#returns the length of the password file in AES blocks
def get_pfile_len():
    if not isfile(PFILE_URL):
        return 0
    else:
        pfile = open(PFILE_URL, 'rb')
        pfile_ct = pfile.read()
        pfile.close()
        return int(len(pfile_ct)/AES.block_size)


def selective_encrypt(data, index):
    nonce = retrieve_nonce()
    ENC = AES.new(enc_key, AES.MODE_CTR, nonce=nonce, initial_value=index)
    encrypted = ENC.encrypt(data)
    return encrypted

def selective_decrypt(index): #spaghetti code warning
    nonce = retrieve_nonce()
    block_offset = 0
    DEC = AES.new(enc_key, AES.MODE_CTR, nonce=nonce, initial_value=index+block_offset)
    file_pos = index * AES.block_size
    pfile = open(PFILE_URL, 'rb')
    pfile_ct = pfile.read()
    first_block = pfile_ct[file_pos:file_pos+AES.block_size]
    fb_dectrypted = DEC.decrypt(first_block)
    try:
        pw_bytes = unpad(fb_dectrypted, AES.block_size)
    except ValueError:
        #not done yet
        blocks_dec = fb_dectrypted
        done = False
        while not done:
            block_offset += 1
            DEC = AES.new(enc_key, AES.MODE_CTR, nonce=nonce, initial_value=index+block_offset)
            block = pfile_ct[(index + block_offset)*AES.block_size:(index + block_offset+1)*AES.block_size]
            decrypted_block = DEC.decrypt(block)
            blocks_dec += decrypted_block
            try:
                pw_bytes = unpad(blocks_dec, AES.block_size)
                done = True
            except ValueError:
                pass
    return pw_bytes


def retrieve_nonce():
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
    print(acct_directory)
    for i in range(0,len(acct_directory)):
        print ('Service: ', acct_directory[i]['Name'])
        print ('URL: ', acct_directory[i]['URL'])
        print ('Username: ', acct_directory[i]['Username'])
        print('')


def search_by_service_name(name):
    global acct_directory
    if not acct_directory:
        load_directory()
    #a list of indices into the account directory of the accounts 
    #that match the parameters
    accts_that_match = []
    for i in range(0, len(acct_directory)):
        if acct_directory[i]['Name'] == name:
            accts_that_match.append(i)
    return accts_that_match

def search_by_url(url):
    global acct_directory
    if not acct_directory:
        load_directory()
    #a list of indices into the account directory of the accounts 
    #that match the parameters
    accts_that_match = []
    for i in range(0, len(acct_directory)):
        if acct_directory[i]['URL'] == url:
            accts_that_match.append(i)
    return accts_that_match

def search_by_username(username):
    global acct_directory
    if not acct_directory:
        load_directory()
    #a list of indices into the account directory of the accounts 
    #that match the parameters
    accts_that_match = []
    for i in range(0, len(acct_directory)):
        if acct_directory[i]['Username'] == username:
            accts_that_match.append(i)
    return accts_that_match


def change_master_pw(new_pw):
    global enc_key
    global mac_key
    global ver_key

    new_enc_key = PBKDF2(new_pw, enc_salt, count=10000)
    new_mac_key = PBKDF2(new_pw, mac_salt, count=10000)
    new_ver_key = PBKDF2(new_pw, ver_salt, count=10000)
    new_pfile_nonce = get_random_bytes(8)
    new_directory_iv = get_random_bytes(AES.block_size)
    del(new_pw)

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

    MAC = HMAC.new(new_mac_key, digestmod=SHA256)
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

    #put a MAC on the pfile
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

    
#delete an account
def delete_acct(acct_index):
    global acct_directory
    if not acct_directory:
        load_directory()

    #get the password index and the length of the stored password in blocks
    pw_idx = int(acct_directory[acct_index]['PW_index'])
    if acct_index+1 < len(acct_directory):
        pw_block_length = int(acct_directory[acct_index+1]['PW_index']) - pw_idx
    else:
        pfile_len = get_pfile_len()
        pw_block_length = pfile_len - pw_idx
    #remove the account from the account directory and rewrite the file
    del acct_directory[acct_index]
    write_acct_info_file()
    #overwrite the password in the password file
    delete_password(pw_idx, pw_block_length)


#delete a password
def delete_password(pw_index, pw_length):
    pw_start = pw_index * AES.block_size
    pw_end = (pw_index + pw_length) * AES.block_size
    pfile = open(PFILE_URL, 'rb')
    pfile_ct = pfile.read()
    pfile.close()

    first_chunk = pfile_ct[:pw_start]
    second_chunk = pfile_ct[pw_end:]
    rand_bytes = get_random_bytes(pw_length * AES.block_size)

    new_pfile_ct = first_chunk + rand_bytes + second_chunk
    pfile = open(PFILE_URL, 'wb')
    pfile.write(new_pfile_ct)
    pfile.close()


def copy_pw(acct_index):
    account = acct_directory[acct_index]
    pw_index = account['PW_index']
    #decrypt the selected password
    pw_bytes = selective_decrypt(pw_index)
    pw_to_copy = pw_bytes.decode('utf-8')
    pyperclip.copy(pw_to_copy)

    
def proceed_if_valid_login():
    if not check_login_valid():
        print('Your login window has expired. Please restart the program to continue')
        exit()


def modify_acct(index):
    service_name = input('Service Name: ')
    service_url = input('URL: ')
    username = input('Username: ')
    use_own_pw = input('Use own password (y) or random password (anything else)?')
    if use_own_pw == 'y':
        password = getpass.getpass()
    else:
        password = get_random_pw()
    register_acct(service_name, service_url, username, password)
    delete_acct(index)

    
def secure_exit():
    global mac_key
    global enc_key
    #put a MAC on the pfile
    pfile = open(PFILE_URL, 'rb')
    pfile_ct = pfile.read()
    pfile.close()
    nonce_file = open(PFILE_NONCE_URL, 'rb')
    nonce = nonce_file.read()
    nonce_file.close()

    pfile_mac_file = open(PFILE_MAC_URL, 'wb')
    PF_MAC = HMAC.new(mac_key, digestmod=SHA256)
    PF_MAC.update(nonce)
    PF_MAC.update(pfile_ct)
    pfile_mac_file.write(PF_MAC.digest())
    pfile_mac_file.close()

    #for what it's worth, del these two
    del(mac_key)
    del(enc_key)

def check_pfile_mac():
    pfile = open(PFILE_URL, 'rb')
    pfile_ct = pfile.read()
    pfile.close()
    nonce_file = open(PFILE_NONCE_URL, 'rb')
    nonce = nonce_file.read()
    nonce_file.close()

    pfile_mac_file = open(PFILE_MAC_URL, 'rb')
    PF_MAC = HMAC.new(mac_key, digestmod=SHA256)
    PF_MAC.update(nonce)
    PF_MAC.update(pfile_ct)
    comp_mac = PF_MAC.digest()

    pfile_saved_mac = pfile_mac_file.read()
    pfile_mac_file.close()
    if not comp_mac == pfile_saved_mac:
        print('MAC verification failed')
        exit()
