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

VERIFICATION_HASH_URL = 'verification-hash'

RAND_PW_SIZE = 14

DIRECTORY_URL = 'directory'
PFILE_URL = 'pfile'
PFILE_NONCE_URL = 'pfile-nonce'

MAC_LENGTH = 32

#lateinits
key:bytes = None
login_time = None
acct_directory:list = None

#When we logout, we are going to have to copy acct_directory to the proper file

#login
#potential security improvements:
#   1. Move these functions into interface to reduce password copies on stack
#   alternatively, call functions that write over stack afterwards
#   (Scratch that, CPython only allocates on heap. Wonderful.)
#   2. Generate salts when master password is created/changed
#   3. Check login validity on a separate thread that waits

def check_login_valid():
    td = datetime.datetime.now()
    sess_len = td.seconds # is this checking the seconds timestamp or the length of the session in seconds? It seems like the former. If so, how is this helpful?
    return sess_len > 0 and sess_len < 300

def verify_password(p):
    ver_key = PBKDF2(p, ver_salt, count=10000)
    vhash_file = open(VERIFICATION_HASH_URL, 'rb')
    vhash = vhash_file.read()
    return ver_key == vhash

def derive_enc_key(p):
    key = PBKDF2(p, enc_salt, count=10000)
    set_login_time()

def set_login_time():
    login_time = datetime.datetime.now()

#setup
#May be an opportune time to create data files, otherwise we can
#(probably) do it lazily
def setup(p):
    ver_key = PBKDF2(p, ver_salt, count=10000)
    vhash_file = open(VERIFICATION_HASH_URL, 'wb+')
    vhash_file.write(ver_key)
    #do we want to close this file?

def check_good_pw(p):
    good_len = len(p) >= 10
    good_uc = any(char in string.uppercase for char in p)
    good_lc = any(char in string.lowercase for char in p)
    good_sc = any(char in string.punctuation for char in p)
    good_num = any(char in string.digits for char in p)
    return good_len and good_uc and good_lc and good_sc and good_num


#registering an account
def register_acct(name, url, username, password):#TODO
    if not acct_directory:
        load_directory()
    index = get_pfile_len()
    new_entry = {"Name":name, "URL":url, "Username":username, "PW_index":index}
    add_pw_to_pfile(password)
    acct_directory.append() #do we need to specify that we're appending new_entry?
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
    if not isfile(DIRECTORY_URL):
        print('No directory file, creating empty list')
        acct_directory = []
        return

    print('Found directory file, decrypting...')
    ifile = open(DIRECTORY_URL, 'rb')
    ciphertext = ifile.read()
    ifile.close()

    # read the encrypted iv, ciphertext, MAC from file
    iv_ct = ciphertext[:AES.block_size]
    mac = ciphertext[-MAC_LENGTH:]
    ciphertext = ciphertext[AES.block_size:-MAC_LENGTH]

    #verify the MAC (could be moved to login, but not necessary)
    MAC = HMAC.new(key, digestmod=SHA256)
    MAC.update(iv)
    MAC.update(ciphertext)
    comp_mac = MAC.digest()
    if comp_mac != mac:
        print('MAC verification failed')
        exit()

    #decrypt the data
    ENC = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = ENC.decrypt(ciphertext)
    decrypted = unpad(decrypted, AES.block_size)

    #load the list
    acct_directory = json.loads(decrypted)

def add_pw_to_pfile(password): #NEEDS TO BE FINISHED
    #convert password string to bytes for encryption
    pb = bytes(password, 'utf-8')
    #pad to create password block(s)
    pb_padded = pad(pb, AES.block_size)
    #encrypt the block(s)
    index = get_pfile_len()
    new_ct = selective_encrypt(pb_padded, index)
    #append the encrypted block to the password file
    if not isfile(PFILE_URL):
    	#create the pfile
    	#write new_ct to the pfile
    else:
    	pfile = open(PFILE_URL, 'wb')
    	pfile.write(new_ct)
    	pfile.close()
    #do we want to increment the nonce here? Or are we just incrementing the index?
    pass

#returns the length of the password file in AES blocks
def get_pfile_len():
    if not isfile(PFILE_URL):
        return 0
    else:
        pfile = open(PFILE_URL, 'rb')
        pfile_ct = pfile.read()
        pfile.close()
        return len(pfile_ct)/AES.block_size

        #Should we have a MAC on the pfile?


def selective_encrypt(data, index): #Finished, i think
    nonce = retrieve_nonce()
    ENC = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=index)#check that this works as intended
    encrypted = ENC.encrypt(data)
    return encrypted


def retrieve_nonce(): #TODO, obviously
#do we want to store the nonce as plaintext?
    if not isfile(PFILE_NONCE_URL):
   		nonce = Random.get_random_bytes(8)
   		#create the nonce file and write to it
        return nonce
    else:
    	nfile = open(PFILE_NONCE_URL, 'rb')
    	nonce = nfile.read()
    	nfile.close()
        return nonce


def print_accts():
	if not acct_directory:
        load_directory()
    #do we want to alphabetize by service name?
    for i in range(0,len(acct_directory)-1):
   		print 'Service: ', acct_directory[i]['Name']
   		print 'Username: ', acct_directory[i]['Username']
   		print 'URL: ', acct_directory[i]['Url']

pass