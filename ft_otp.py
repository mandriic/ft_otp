import hmac
import os
import struct
import hashlib
import time
import argparse
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode 

def get_hotp_token(secret, intervals_no):
    # key = base64.b16decode(secret, True)
    key = bytes.fromhex(secret)
    #decoding our key
    msg = struct.pack(">Q", intervals_no)
    #conversions between Python values and C structs represente
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = o = h[19] & 15
    #Generate a hash using both of these. Hashing algorithm is HMAC
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    #unpacking
    return h

def get_totp_token(secret):
    #ensuring to give the same otp for 30 seconds
    x =str(get_hotp_token(secret,intervals_no=int(time.time())//30))
    #adding 0 in the beginning till OTP has 6 digits
    while len(x)!=6:
        x ='0' + x
    return x

def get_key(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    return base64.urlsafe_b64encode(digest.finalize())

def encrypt(password, token):
    f = Fernet(get_key(key))
    return f.encrypt(bytes(token))

def decrypt(password, token):
    f = Fernet(get_key(password))
    return f.decrypt(bytes(token))

parser = argparse.ArgumentParser(description="TOTP key generator")
parser.add_argument("-g", help="receive as an argument a hexadecimal key of at least 64 character")
parser.add_argument("-k", help="the program will generate a new temporary password and printit to standard output")
args = parser.parse_args()
if args.g is None and args.k is None:
    parser.print_help()
    parser.exit()
if args.g:
    secret = "0"
    try:
        secret_file = open(args.g, "rb")
        secret = secret_file.read()
    except:
        print("Cant open .hex file")
        print (os._exit(os.EX_DATAERR))
    if not secret or len(secret) < 64:
        print ("Key is less than 64 caracters")
        print (os._exit(os.EX_DATAERR))
    passw = getpass("Enter your pass: ")
    passw = passw.encode('utf-8')
    key = get_key(passw)
    f = Fernet(key)
    try:
        file_open = open("ft_otp.key", "wb")
        token = f.encrypt(secret)
        token_bytearray = bytearray(token)
        file_open.write(token_bytearray)
        file_open.close()
    except Exception as ex:
        print (ex)
if args.k:
    try:
        file_open = open(args.k, "rb")
        text = file_open.read()
    except Exception as ex:
        print (ex)
        os._exit(os.EX_IOERR)
    passw = getpass("Enter your pass: ")
    passw = passw.encode('utf-8')
    key = get_key(passw)
    f = Fernet(key)
    try:
        token = f.decrypt(text)
        token = token.decode("utf-8")
        totp_key = get_totp_token(token)
        print(totp_key)
        img = qrcode.make(totp_key)
        img.save('MyQRCode1.png')
    except Exception as ex:
        print("Invalid key")
        os._exit(os.EX_IOERR)
