#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020, Elias von Däniken
#
# Description:
# This script plays the role of the verifier in the POC for remote attestation.
# It is an interactive CLI-Tool where you can play the role of the verifier and
# get attestation from remote devices. At the beginning are some default values,
# which can be adjusted for easier testing. Normally the commands of the cli are
# executed in order.
#
# Required Python packages:
# - base64
# - ipaddress
# - json
# - os
# - sys
# - Cryptodome
# - pathlib
# - time
# - websocket
#
# Note to Cryptodome:
# The installation of the package Cryptodome is a mess. If you are working with
# ubuntu install Cryptodome via apt with "python3-pycryptodome". If you are
# working with some other system do not install Cryptodome with "pip3 install
# pycryptodome". It will install it in the module Crypto. Instead use "pip3
# install pycryptodomex", which will install it correctly. pycryptodome and
# pycryptodome are the same packages, but will install themselves under
# different namens.

import base64
import ipaddress
import json
import os
import sys

from Cryptodome.Util.Padding import pad
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from pathlib import Path
from time import sleep
from websocket import create_connection

default_ip_addr = "ws://192.168.46.30:16800"
default_path = "/home/evondaeniken/optee-dev-env-rpi3/optee_examples/attestation/scripts/keys/all-b64/pe-key-pub"

CA_public_key = 0
ws = 0
open_conn = False
def cast_public_pem(str_b64):
        header = "-----BEGIN RSA PUBLIC KEY-----\n"
        footer = "\n-----END RSA PUBLIC KEY-----"
        s = header
        rows = int(len(str_b64)/64)
        for i in range(rows):
            s = s + str_b64[i*64:i*64+64]
            s +="\n"
        s = s + str_b64[rows*64:] + footer
        return s

def checkAttCert(cert_string, challenge):
    d = json.loads(cert_string)

    # Validate the Ak Hash
    h = SHA256.new( base64.b64decode( d["cert"]["Attestation Key"]))
    ak_hash = base64.b64encode( h.digest()).decode('utf-8')
    if d["cert"]["Attestation Key Hash"] != ak_hash:
        print("validation of the Ak Hash failed!")
        return True

    # Validate User Data Hash
    h = SHA256.new(challenge)
    ud_hash = base64.b64encode(h.digest()).decode('utf-8')
    if d["cert"]["User Data Hash"] != ud_hash:
        print("validation of the User Data failed!")
        return True

    # Validate the Attestation Data
    h = SHA256.new()
    h.update( base64.b64decode(d["data"]["iv"]))
    h.update( base64.b64decode(d["data"]["pub"]))
    h.update( base64.b64decode(d["data"]["enc_priv"]))
    verifier = pss.new(CA_public_key)
    try:
        verifier.verify(h, base64.b64decode(d["data"]["sig"]))
    except (ValueError, TypeError):
        print("validation of the Attestation Data failed!")
        return True

    # Validate the Attestation Certificate
    h = SHA256.new()
    h.update( base64.b64decode(d["cert"]["Attestation Key Hash"]))
    h.update( base64.b64decode(d["cert"]["TA Hash"]))
    h.update( base64.b64decode(d["cert"]["System Measurement"]))
    h.update( base64.b64decode(d["cert"]["User Data Hash"]))
    key = RSA.import_key(cast_public_pem(d["data"]["pub"]))
    verifier = pss.new(key, salt_bytes=0)
    try:
        verifier.verify(h, base64.b64decode(d["cert"]["Signature"]))
    except (ValueError, TypeError):
        print("validation of the Attestation Certificate failed!")
        return True

    # If everything is Ok
    return False

def setPEkey():
    print("Please type in the path to the PE public key:")
    global CA_public_key, default_path
    ca_key_file = input()

    if not os.path.isfile(ca_key_file):
                print("not a valid path: " + ca_key_file)
                print("use default path : " + default_path)
                ca_key_file = default_path
                if not os.path.isfile(ca_key_file):
                    print("default path invalid")
                    sys.exit(1)

    CA_public_key = RSA.import_key(open(ca_key_file).read())
    print("Public key of the provision entity is set and loaded\n")

    input("Press Enter to continue...")
    os.system('clear')

def openConn():
    global open_conn
    if open_conn:
        print("A connection is already open!")
        input("Press Enter to continue...")
        os.system('clear')
        return

    print("Please type in the ip addres of the TEE:")
    global ws
    global default_ip_addr

    try:
        ip_str = input()
        ip = ipaddress.ip_address(ip_str)
        print('%s is a correct IP%s address.' % (ip, ip.version))
        print("\nPlease type in the port for the connection:")
        port = input()
        addr = "ws://"+ ip_str +":" + port
        print(addr)
    except:
        print('address/netmask is invalid: %s' % ip_str)
        addr = default_ip_addr
        print("using default: " + addr + '\n')

    print("connecting with addr: " + addr )

    try:
        ws = create_connection(addr)
        print("connection opened successful\n")
        open_conn = True
    except:
        print("opening connection failed\n")

    input("Press Enter to continue...")
    os.system('clear')

def getAtt():
    global ws
    if open_conn is False:
        print("Please open a connection first!")
        input("Press Enter to continue...")
        os.system('clear')
        return

    # ask the user for a string
    print("Please type in a random string for the seed of the challenge")
    seed = input()
    h = SHA256.new(seed.encode())
    rn_b = h.digest()
    rn = base64.b64encode(rn_b).decode()

    # requests the attestation certificate and delivers a challenge
    print("The message with the Random Number requests the Attestation Certificate:")
    msg = {
        "id" : 0x01,
        "rn" :  rn
    }
    tx_string = json.dumps(msg)
    print(tx_string)
    ws.send(json.dumps(msg))

    # receive the certificate
    print("\nWaiting for response (may take some time to generate an RSA 2048bit key)")
    while True:
        sleep(0.1)
        response = ws.recv()
        if response:
            break

    # write the att cert to a file
    print("Attestation Certificate received and saved to the file: attestation-certificate.json")
    f = open("attestation-certificate.json", "w")
    f.write(response)
    f.close()

    # validate the certificate
    print("Attestation Certificate validating ...")
    sleep(1)
    if (checkAttCert(response, rn_b)):
        print("Attestation certificate is not valid!")
        input("Press Enter to close the application...")
        ws.close()
        sys.exit(1)
    print("Attestation certificate is valid!")

    # write AK to file: attestation-key.pem
    f = open("attestation-key.pem", "w")
    d = json.loads(response)
    f.write(cast_public_pem(d["cert"]["Attestation Key" ]))
    f.close()
    sleep(0.5)

    # send OK back
    msg = {
        "id" : 0x03
    }
    ws.send(json.dumps(msg))

    # exit
    sys.stdin.flush()
    input("Press Enter to continue...")
    os.system('clear')

def getCounter():
    global ws

    if ws == 0:
        print("Please open a connection first!")
        input("Press Enter to continue...")
        os.system('clear')
        return

    if os.path.isfile("attestation-key.pem") is False:
        print("Please get an attestation certificate first!")
        input("Press Enter to continue...")
        os.system('clear')
        return

    print("The counter certificate is requested\n")
    msg = {
        "id" : 20
    }
    ws.send(json.dumps(msg))

    print("Waiting for response...")
    while True:
        sleep(0.1)
        response = ws.recv()
        if response:
            break

    print("Received\n")
    print(response)
    d = json.loads(response)

    print("Validating...")
    h = SHA256.new()
    h.update( base64.b64decode(d["Counter"]["Value"]))
    key = RSA.import_key(open('attestation-key.pem').read())
    verifier = pss.new(key)
    try:
        verifier.verify(h, base64.b64decode(d["Counter"]["Signature"]))
        print("validation of the counter certificate succeed!\n")
    except (ValueError, TypeError):
        print("validation of the counter certificate failed!")
        sys.exit(1)

    print("The counter value is right now: ", int.from_bytes(base64.b64decode(d["Counter"]["Value"]), byteorder='little', signed=False))

    input("\nPress Enter to continue...")
    os.system('clear')

def incCounter():
    global ws

    if ws == 0:
        print("Please open a connection first!")
        input("Press Enter to continue...")
        os.system('clear')
        return

    print("Incrementing counter")
    msg = {
        "id" : 0x0a
    }
    ws.send(json.dumps(msg))

    print("\nwaiting for response...")
    while True:
        sleep(0.1)
        response = ws.recv()
        if response:
            break
    print("Counter was incremented\n")

    input("Press Enter to continue...")
    os.system('clear')

def exitProg():
    if ws:
        ws.close()
    return sys.exit(0)

def chooser(in_char):
    ch ={
        1 : setPEkey,
        2 : openConn,
        3 : getAtt,
        4 : getCounter,
        5 : incCounter,
        6 : exitProg
    }
    os.system('clear')
    try:
        i = int(in_char)
    except:
        i = 0
    return ch.get(i , lambda: "Invalid")

def main():
    while True:
        print("Which command do you want to execute?")
        print("-1- load the PE public key to validate the Attestation Certificate/Data")
        print("-2- open a connection to a TEE")
        print("-3- get the Attestation Data/Certificate")
        print("-4- get the Counter Certificate")
        print("-5- increment the safest counter in the world")
        print("-6- exit this program")
        chooser(input())()

if __name__ == "__main__":
    main()


