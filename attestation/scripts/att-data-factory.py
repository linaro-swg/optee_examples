#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Elias von Däniken
#
# Description:
# This script can generate and verify attestation data. To generate the
# attestation data a lot of keys are required for reference take a look
# at keys folder in the POC. Also the sample calls can help.
#
# Required Python packages:
# - argparse
# - base64
# - Cryptodome
# - json
# - pathlib
# - os
# - sys
#
# Note to Cryptodome:
# The installation of the package Cryptodome is a mess. If you are working with
# ubuntu install Cryptodome via apt with "python3-pycryptodome". If you are
# working with some other system do not install Cryptodome with "pip3 install
# pycryptodome". It will install it in the module Crypto. Instead use "pip3
# install pycryptodomex", which will install it correctly. pycryptodome and
# pycryptodome are the same packages, but will install themselves under
# different namens.
#
# Sample Call
# ./att-data-factory.py generate --ca-pub-b64 keys/all-b64/pe-key-pub --ca-priv-b64 keys/all-b64/pe-key-priv  --IV-b64 keys/all-b64/IV --EK-b64 keys/all-b64/EK --AIK-pub-b64 keys/all-b64/AIK-pub  --AIK-priv-b64 keys/all-b64/AIK-priv -o keys
# ./att-data-factory.py verify --cert-b64 keys/cert-b64.json --ca-pub-b64 keys/all-b64/pe-key-pub


import base64
import json
import os
import sys

from argparse import ArgumentParser
from Cryptodome.Util.Padding import pad
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from pathlib import Path

def convert_cert(cert, direction):
    def conv(direction, args):
        if direction == 'bytes to b64': return base64.standard_b64encode(args).decode()
        if direction == 'bytes to hex': return bytes.fromhex(args)
        if direction == 'b64 to bytes': return base64.standard_b64decode(args)
        if direction == 'hex to bytes': return bytes.hex(args)

    return {
            "header" : {
                "iv_size" : conv(direction, cert["header"]["iv_size"]),
                "pub_size" : conv(direction, cert["header"]["pub_size"]),
                "enc_priv_size" : conv(direction, cert["header"]["enc_priv_size"]),
                "sig_size" : conv(direction, cert["header"]["sig_size"])
            },
            "iv" : conv(direction, cert["iv"]),
            "pub" : conv(direction, cert["pub"]),
            "enc_priv" : conv(direction, cert["enc_priv"]),
            "sig" : conv(direction, cert["sig"])
        }

def encode_file_base64(file_str):
    f = open(file_str, "r")
    s = f.read(1)
    f.seek(0)
    if s == "-":
        s = f.readlines()
        s = "".join(s[1:-1])
    else:
        s = f.read()
    b = base64.standard_b64decode(s)
    f.close()
    return b

def encode_file_hex(file_str):
    f = open(file_str, "r")
    s = f.read()
    b = bytes.fromhex(s)
    f.close()
    return b

def check_args(arg_b64 , arg_hex, cert):
    if arg_b64 and arg_hex:
        sys.exit(1)

    if arg_hex:
        if os.path.isfile(arg_hex):
            if cert:
                with open(arg_hex) as json_file:
                    return convert_cert( 'hex to bytes', json.load(json_file))
            return encode_file_hex(arg_hex)
        print("not a valid path: " + arg_hex)
        sys.exit(1)

    if arg_b64:
        if os.path.isfile(arg_b64):
            if cert:
                with open(arg_b64) as json_file:
                    return convert_cert( 'b64 to bytes', json.load(json_file))
            return encode_file_base64(arg_b64)
        print("not a valid path: " + arg_b64)
        sys.exit(1)

def get_args():
    command_base = ['generate', 'verify']

    command_choices = command_base

    parser = ArgumentParser(
        description='can forge/validate attestation data for remote attestation' +
        ' OP-TEE.',
        usage='\nCommand to create Attestation Data: \n\n \
         att-data-factory generate \n \
            --ca-pub-b64 <path/to/public-key-from-CA>\n \
            --ca-priv-b64 <path/to/private-key-from-CA>\n \
            --IV-b64 <path/to/IV-for-AES-CBC>\n \
            --EK-b64 <path/to/public-key-from-CA>\n \
            --AIK-pub-b64 <path/to/public-key-to-embedd-into-the-certificate>\n \
            --AIK-priv-b64 <path/to/private-key-to-embedd-into-the-certificate>\n \
            \n\n \
            All of these files can either be in Hex or Base64, only change the ending of the command\n \
            Check the source code of the scrip for further information.'
        )

    parser.add_argument(
        'command', choices=command_choices, nargs='?',
        default='generate',
        help='Command, one of [' + ', '.join(command_base) + ']')


    # ---------------- Base64 Arguments
    parser.add_argument(
        '--ca-pub-b64', dest='pub_ca_64',
        help='Path to the public Key of the CA (encoded in base64)')

    parser.add_argument(
        '--ca-priv-b64', dest='priv_ca_64',
        help='Path to the private Key of the CA (encoded in base64)')

    parser.add_argument(
        '--AIK-pub-b64', dest='pub_cert_64',
        help='Path to the public Key, which gets into the attestation data (encoded in base64)')

    parser.add_argument(
        '--AIK-priv-b64', dest='priv_cert_64',
        help='Path to the private Key, which gets into the attestation data (encoded in base64)')

    parser.add_argument(
        '--EK-b64', dest='end_key_64',
        help='Endorsement Key, used to encrypt the priv-cert key (encoded in base64)')

    parser.add_argument(
        '--IV-b64', dest='end_iv_64',
        help='IV for the AES-GCM,  used for the endorsement key (encoded in base64)')

    # ---------------- hex arguments
    parser.add_argument(
        '--ca-pub-hex', dest='pub_ca_hex',
        help='Path to the public Key of the CA (encoded in hex)')

    parser.add_argument(
        '--ca-priv-hex', dest='priv_ca_hex',
        help='Path to the private Key of the CA (encoded in hex)')

    parser.add_argument(
        '--AIK-pub-hex', dest='pub_cert_hex',
        help='Path to the public Key, which gets into the attestation data (encoded in hex)')

    parser.add_argument(
        '--AIK-priv-hex', dest='priv_cert_hex',
        help='Path to the private Key, which gets into the attestation aata (encoded in hex)')

    parser.add_argument(
        '--EK-hex', dest='end_key_hex',
        help='Endorsement Key, used to encrypt the priv-cert key (encoded in hex)')

    parser.add_argument(
        '--IV-hex', dest='end_iv_hex',
        help='IV for the AES-GCM,  used for the endorsement key (encoded in hex)')

    # ---------------- verify argument
    parser.add_argument(
        '--cert-hex', dest='cert_hex',
        help='Atesstation Data (encoded in hex)')

    parser.add_argument(
        '--cert-b64', dest='cert_b64',
        help='Atesstation Data (encoded in base64)')

    # ---------------- output directory
    parser.add_argument(
        '-o', dest='path',
        help='output directory')


    parsed = parser.parse_args()

    if parsed.path is not None and not os.path.isdir(parsed.path):
        print("not a valid path" + parsed.path)
        sys.exit(1)

    return parsed

def main():
    args = get_args()

    # Check for bad combinations of Parameter
    input_data = {}
    input_data["pub_ca"] =    check_args(args.pub_ca_64   , args.pub_ca_hex   , False)
    input_data["priv_ca"] =   check_args(args.priv_ca_64  , args.priv_ca_hex  , False)
    input_data["pub_cert"] =  check_args(args.pub_cert_64 , args.pub_cert_hex , False)
    input_data["priv_cert"] = check_args(args.priv_cert_64, args.priv_cert_hex, False)
    input_data["end_key"] =   check_args(args.end_key_64  , args.end_key_hex  , False)
    input_data["end_iv"] =    check_args(args.end_iv_64   , args.end_iv_hex   , False)
    input_data["cert"] =      check_args(args.cert_b64    , args.cert_hex     , True)


    # Check that all necessary inputs exist
    if args.command == 'generate':
        if input_data["priv_ca"] == False:
            print("private Key of the CA is necessary to forge a certificate")
            sys.exit(1)
        if input_data["pub_cert"] == False:
            print("public Key is necessary to forge a certificate")
            sys.exit(1)
        if input_data["priv_cert"] == False:
            print("private Key is necessary to forge a certificate")
            sys.exit(1)
        if input_data["end_key"] == False:
            print("endorsement key is necessary to forge a certificate")
            sys.exit(1)
        if input_data["end_iv"] == False:
            print("endorsement IV is necessary to forge a certificate")
            sys.exit(1)

    if args.command == 'verify':
        if input_data["pub_ca"] == False:
            print("public Key of the CA is necessary to validate the certificate")
            sys.exit(1)
        if input_data["cert"] == False:
            print("te certificate is necessary to validate the certificate ;)")


    def generate():
        # encrypt the private key
        engine = AES.new(input_data["end_key"], AES.MODE_CBC,  input_data["end_iv"])
        enc_priv =  engine.encrypt(pad(input_data["priv_cert"], AES.block_size))

        # calculate the hash
        h = SHA256.new()
        h.update(input_data["end_iv"])
        h.update(input_data["pub_cert"])
        h.update(enc_priv)

        # forge the signature
        key = RSA.import_key(input_data["priv_ca"])
        sig = pss.new(key).sign(h)

        # fill out the header
        header = {}
        header["iv_size"] = len(input_data["end_iv"]).to_bytes(4, 'big')
        header["pub_size"] = len(input_data["pub_cert"]).to_bytes(4, 'big')
        header["enc_priv_size"] = len(enc_priv).to_bytes(4, 'big')
        header["sig_size"] = len(sig).to_bytes(4, 'big')

        # fill out the certificate
        iv = input_data["end_iv"]
        pub_key = input_data["pub_cert"]
        cert ={
            "header" : header,
            "iv" : iv,
            "pub" : pub_key,
            "enc_priv" : enc_priv,
            "sig" : sig
        }

        # prepare output filenames if exist
        if  args.path is None:
            out_file_b64 = "cert-b64.json"
        else:
            path = Path(args.path)
            out_file_b64 = path / "cert-b64.json"

        # write certificate in base64 to file
        cert_file = open( out_file_b64, "w")
        json.dump(convert_cert(cert, 'bytes to b64'), cert_file, indent=4)
        cert_file.close()

        print("certificate was successfully forged")


    def verify():
        c = input_data["cert"]

        # calculate the hash
        h = SHA256.new()
        h.update(c["iv"])
        h.update(c["pub"])
        h.update(c["enc_priv"])

        # validate signature
        key = RSA.import_key(input_data["pub_ca"])
        verifier = pss.new(key)
        try:
            verifier.verify(h, c["sig"])
            print("The signature is authentic.")
        except (ValueError, TypeError):
            print("The signature is not authentic.")

    # dispatch command
    {
        'generate': generate,
        'verify': verify,
    }.get(args.command, 'generate')()

if __name__ == "__main__":
    main()