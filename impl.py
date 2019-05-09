#
#
#   The implementations. All crypto details go here. Called by interface
#
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import datetime
import string

#login
#potential security improvements:
#   1. Move these functions into interface to reduce password copies on stack
#   alternatively, call functions that write over stack afterwards
#   2. Generate salts when master password is created/changed
#   3. Check login validity on a separate thread that waits

ver_salt = '12345678'
enc_salt = '90abcdef'

VERIFICATION_HASH_URL = 'verification-hash'

UC = 'QWERTYUIOPASDFGHJKLZXCVBNM'
LC = 'qwertyuiopasdfghjklzxcvbnm'
NUMS = '1234567890'
#Yes, there is probably a better way to do this
#The advantage here is that we don't pass p to another stack frame

key = None
login_time = None

def check_login_valid():
    td = datetime.datetime.now()
    sess_len = td.seconds
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

def check_good_pw(p):
    good_len = len(p) >= 10
    good_uc = any(char in UC for char in p)
    good_lc = any(char in LC for char in p)
    good_sc = any(char in string.punctuation for char in p)
    good_num = any(char in NUMS for char in p)
    return good_len and good_uc and good_lc and good_sc
