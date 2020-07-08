#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Elias von Däniken
#
# Description:
# This script helps to analyze a compiled TA. It scans the TA binary reads the
# signed header and prints out the its elements. It does not check the hash or
# the signature. All the outputs are in hex format.
#
# Required Python packages:
# - argparse
# - codecs
# - os
# - struct
# - sys
# - uuid
#
# Sample Call
# analyze-ta.py ~/optee-dev-setup/optee_examples/attestation/ta/c615b83b-c264-4bd7-8a8c-8b08a59350db.ta

def get_args():
    from argparse import ArgumentParser
    import os
    import sys

    command_base = ['all', 'shdr', 'shdr_uuid', 'shdr_version', 'digest_b64', 'sig']
    command_choices = command_base

    parser = ArgumentParser(
        description='Analyzes the header of a TA OP-TEE.',
        usage='\n  analyze-ta command <path-to-ta>/<ta>\n\n'
        )

    parser.add_argument(
        'command', choices=command_choices, nargs='?',
        default='all',
        help='Command, one of [' + ', '.join(command_base) + ']')

    parser.add_argument(
        'ta',
        help='Path to the TA folder')


    parsed = parser.parse_args()

    if not os.path.isfile(parsed.ta):
        print("Invalid file name: " + parsed.ta)
        sys.exit(1)

    return parsed

def main():
    from pathlib import Path
    import codecs
    import os
    import struct
    from uuid import UUID

    args = get_args()

    with open(args.ta, 'rb') as f:
        shdr_of_bin = struct.unpack('<IIIIHH',f.read(20))
        digest_of_bin = f.read( shdr_of_bin[4]).hex()
        sig_of_bin = f.read( shdr_of_bin[5]).hex()
        uuid_of_bin = UUID(f.read(16).hex())
        version_of_bin = struct.unpack('<I', f.read(4))

    def print_all():
        print(" _______________________________ ")
        print("| Signed Header (shdr)          |")
        print("|_______________________________|")
        print("| magic:", hex(shdr_of_bin[0]), "            |")
        print("| img_type:", hex(shdr_of_bin[1]), "                |")
        print("| img_size: ", shdr_of_bin[2], "bytes       |")
        print("| algo: ", hex(shdr_of_bin[3]), "            |")
        print("| digest_len:", shdr_of_bin[4], "bytes          |")
        print("| sig_len:", shdr_of_bin[5], "bytes            |")
        print("|_______________________________|")
        print()
        print(" _______________________________ ")
        print("|Digest of the binary(aka Hash) |")
        print("|_______________________________|")
        for x in range(int(shdr_of_bin[4]/8)):
            print("| ",digest_of_bin[x*16:x*16+16], "             |")
        print("|_______________________________|")
        print()
        print(" _______________________________ ")
        print("|Signature of the binary        |")
        print("|_______________________________|")
        for x in range(int(shdr_of_bin[5]/8)):
            print("| ",sig_of_bin[x*16:x*16+16], "             |")
        print("|_______________________________|")
        print()
        print("UUID:")
        shdr_uuid()
        print ()
        print("Version:")
        shdr_version()

    def shdr():
        print("magic:", hex(shdr_of_bin[0]))
        print("img_type:", hex(shdr_of_bin[1]))
        print("img_size: ", shdr_of_bin[2], "bytes")
        print("algo: ", hex(shdr_of_bin[3]))
        print("digest_len:", shdr_of_bin[4], "bytes")
        print("sig_len:", shdr_of_bin[5], "bytes")

    def shdr_uuid():
        print(uuid_of_bin)

    def shdr_version():
        print(version_of_bin[0])

    def digest():
        print(codecs.encode(codecs.decode(digest_of_bin, 'hex'), 'base64').decode())

    def sig():
        print(sig_of_bin)

    # dispatch command
    {
        'all': print_all,
        'shdr': shdr,
        'digest_b64':digest,
        'sig':sig,
        'shdr_uuid': shdr_uuid,
        'shdr_version': shdr_version,
    }.get(args.command)()

if __name__ == "__main__":
    main()