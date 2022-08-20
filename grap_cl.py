#!/usr/bin/env python
from operator import sub
import os
from turtle import color
import PySimpleGUI as sg
import base64
import hashlib
import hmac
import os
import struct
import hashlib
import time
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode 
import subprocess

sg.theme('Tan')

tab1_layout = [
                [sg.Text('Plain text to HEX converter', font='_ 13'), ],
                [sg.Input("Enter your text",key='-in0-')],
                [sg.Multiline('HEX', key="-HEX-", expand_x=1, expand_y=1)],
                [sg.Button('Convert', key="-tab1-"), sg.Button('Save to file key.hex', key=('-SAVE-'))]
               ]

tab2_layout = [
                [sg.Text('Save HEX to ft_otp.key ', font='_ 13')], # at least 64 caracters
                [sg.FileBrowse(key=("-FILEBR-")), sg.Button('Read', key="-readhex-")],
               ]
    
tab3_layout = [
                [sg.Text('TOTP generate from ft_otp.key', font='_ 13')],
                [sg.Text('Chose ft_otp.key file')],
                [sg.FileBrowse(key=("-FILEKEY-")), sg.Button('Load file', key=("-READKEY-"))],
                [sg.Text('Your code is:'), sg.Text(text_color=("red"), key=("-TEXTKEY-")), sg.Text("Oathtool-check: "), sg.Text(text_color=("red"), key=("-OATH-"))],
                [sg.Image(filename=None, expand_x=1, expand_y=1 ,key=("-QRCODE-"))]
               ]


layout = [[sg.TabGroup([[sg.Tab('Convert TEXT 2 HEX', tab1_layout, key='-mykey-'),
                         sg.Tab('Create ft_otp.key', tab2_layout),
                         sg.Tab('TOTP generate from .key', tab3_layout)],],size=(200, 400),
                       key='-group2-',
                       tab_location='top')]]

window = sg.Window('ft_opt', layout)

def get_key(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    return base64.urlsafe_b64encode(digest.finalize())

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

while True:
    event, values = window.read()
    # sg.popup_non_blocking(event, values)
    # print(event, values)
    if event == sg.WIN_CLOSED:           # always,  always give a way out!
        break
    if event == '-tab1-':
        # print (values['-in0-'])
        text = values['-in0-']
        text = str.encode(text)
        text2hex = base64.b16encode(text)
        window['-HEX-'].update(text2hex.decode())
    if event == '-SAVE-':
        if len (text2hex.decode()) > 64:
            try:
                file_open = open("key.hex", "wb")
                file_open.write(text2hex)
                file_open.close()
                sg.popup_non_blocking("key.hex file was created")
            except Exception as ex:
                sg.popup_error (ex)
        else:
            sg.popup_error("hex file need more than 64 caracteres")
    if event == "-readhex-":
        # print (values['-FILEBR-'])
        secret = "0"
        try:
            secret_file = open(values['-FILEBR-'], "rb")
            secret = secret_file.read()
        except:
            sg.popup_error("Cant open .hex file")
            # print (os._exit(os.EX_DATAERR))
        if not secret or len(secret) < 64:
            sg.popup_error("Key is more than 64 caracters")
            # print (os._exit(os.EX_DATAERR))
        passw = sg.popup_get_text(
        'Create Password for ft_opt.key: ', password_char='*')
        if not passw:
            sg.popup_error("You need enter password for .key file", auto_close=False)
            continue
        passw = passw.encode('utf-8')
        key = get_key(passw)
        f = Fernet(key)
        try:
            file_open = open("ft_otp.key", "wb")
            token = f.encrypt(secret)
            token_bytearray = bytearray(token)
            file_open.write(token_bytearray)
            file_open.close()
            sg.popup_non_blocking("Key was created")
        except Exception as ex:
             sg.popup_error (ex)
    if event == "-READKEY-": 
        try:
            file_open = open(values['-FILEKEY-'], "rb")
            text = file_open.read()
        except Exception as ex:
            sg.popup_error (ex)
            os._exit(os.EX_IOERR)
        passw = sg.popup_get_text(
        'Enter password of your ft_opt.key file: ', password_char='*')
        if not passw:
            sg.popup_error("You need enter password for .key file", auto_close=False)
            continue
        passw = passw.encode('utf-8')
        key = get_key(passw)
        f = Fernet(key)
        try:
            token = f.decrypt(text)
            token = token.decode("utf-8")
            totp_key = get_totp_token(token)
            # print(totp_key)
            img = qrcode.make(totp_key)
            img.save('MyQRCode1.png')
            keyhex = open("key.hex").read()
            oathkey = subprocess.check_output(['oathtool', '--totp', keyhex])
            window["-TEXTKEY-"].update(totp_key)
            window["-QRCODE-"].update(filename="MyQRCode1.png")
            window["-OATH-"].update(str.strip(oathkey.decode()))

        except Exception as ex:
            sg.popup_error(ex)
            sg.popup_error("Invalid key or file")
            # os._exit(os.EX_IOERR)
window.close()
