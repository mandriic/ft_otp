#!/usr/bin/env python
import os
import sys
import PySimpleGUI as sg
import base64
import hashlib
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
# import PySimpleGUIWeb as sg

# Usage of Tabs in PSG
#
# sg.set_options(background_color='cornsilk4',
#         element_background_color='cornsilk2',
#         input_elements_background_color='cornsilk2')
filename = None
sg.theme('Tan')

tab1_layout = [[sg.Text('Plain text to HEX converter'), ],
               [sg.Input("Enter your text",key='-in0-')],
               [sg.Multiline('HEX', key="-HEX-")],
               [sg.Button('Do it', key="-tab1-")]]

tab2_layout = [[sg.Text('Save HEX to ft_otp.key ')], # at least 64 caracters
               [sg.FileBrowse(key=("-FILEBR-")), sg.Button('Read', key="-readhex-")]]
    


tab3_layout = [[sg.Text('TOTP generate from ft_otp.key')],
                [sg.Text('Chose ft_otp.key file')],
               [sg.FileBrowse(key=("-FILEKEY-")), sg.Button('Load', key=("-READKEY-"))],
                [sg.Text('Your code is:'), sg.Text(key=("-TEXTKEY-"))],
                [sg.Image(filename=None, expand_x=1, expand_y=1 ,key=("-QRCODE-"))]

               ]


layout = [[sg.TabGroup([[sg.Tab('Convert TEXT 2 HEX', tab1_layout, key='-mykey-'),
                         sg.Tab('Create ft_otp.key', tab2_layout),
                         sg.Tab('TOTP generate from .hex', tab3_layout)],],size=(200, 400),
                       key='-group2-',
                       tab_location='top')]]
        #    sg.TabGroup([[sg.Tab('Tab 4', tab4_layout, background_color='darkseagreen', key='-mykey-'),
                        #  sg.Tab('Tab 5', tab5_layout)]], key='-group1-', tab_location='top', selected_title_color='purple')],
          # [sg.TabGroup([[sg.Tab('Tab 1', tab1_layout, background_color='darkslateblue', key='-mykey-'),
          #                sg.Tab('Tab 2', tab2_layout, background_color='tan1'),
          #                sg.Tab('Tab 3', tab3_layout)]],
          #              key='-group3-', title_color='red',
          #              selected_title_color='green', tab_location='left'),
          #  sg.TabGroup([[sg.Tab('Tab 4', tab4_layout, background_color='darkseagreen', key='-mykey-'),
          #                sg.Tab('Tab 5', tab5_layout)]], key='-group4-', tab_location='bottom', selected_title_color='purple')],
          

window = sg.Window('My window with tabs', layout)

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
        x+='0'
    return x

while True:
    event, values = window.read()
    # sg.popup_non_blocking(event, values)
    # print(event, values)
    if event == sg.WIN_CLOSED:           # always,  always give a way out!
        break
    if event == '-tab1-':
        print (values['-in0-'])
        text = values['-in0-']
        text = str.encode(text)
        text2hex = base64.b16encode(text)
        window['-HEX-'].update(text2hex.decode())
    if event == "-readhex-":
        print (values['-FILEBR-'])
        secret = "0"
        try:
            secret_file = open(values['-FILEBR-'], "rb")
            secret = secret_file.read()
        except:
            sg.popup_error("POPUP Cant open .hex file")
            # print (os._exit(os.EX_DATAERR))
        if not secret or len(secret) < 64:
            sg.popup_error("Key is more than 64 caracters")
            # print (os._exit(os.EX_DATAERR))
        passw = sg.popup_get_text(
        'Password: ', password_char='*')
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
        'Password: ', password_char='*')
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
        except Exception as ex:
            sg.popup_error(ex)
            sg.popup_error("Invalid key")
            # os._exit(os.EX_IOERR)
        window["-QRCODE-"].update(filename="MyQRCode1.png")
        window["-TEXTKEY-"].update(totp_key)
window.close()
