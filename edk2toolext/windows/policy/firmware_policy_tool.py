# @file
# Basic command-line interface for creating
# and decoding Windows Firmware Policy blobs
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

from edk2toollib.windows.policy.firmware_policy import FirmwarePolicy
import argparse
from OpenSSL import crypto
from cryptography.fernet import Fernet


def PrintPolicy(filename: str) -> None:
    """Attempts to parse filename as a Windows Firmware Policy and print it"""
    try:
        with open(filename, 'rb') as f:
            b = bytes(f.read())
            try: 
                p7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, b)
            except:
                p7 = None
            if p7:
                typeName = p7.get_type_name()
                typeString = str(typeName)
                if typeName != b'pkcs7-signedData':
                    print("P7: Expected pkcs7-signedData, found " + typeString)
                    return
                print('P7: ' + typeString)
                #crypto._lib
                test = crypto._lib.OBJ_obj2nid( p7._pkcs7.d.sign.contents )
            else:
                f.seek(0)
            policy = FirmwarePolicy(fs=f)
            policy.Print()

    except FileNotFoundError:
        print('ERROR:  File not found: "{0}"'.format(filename))


def CreatePolicyFromParameters(filename: str, manufacturer: str, product: str,
                               sn: str, nonce: int, oem1: str, oem2: str, devicePolicy: int) -> None:
    """
    Populates a Windows FirmwarePolicy object with the provided parameters and serializes it to filename

    Filename must be a new file, will not overwrite existing files.
    """
    with open(filename, 'xb') as f:
        policy = FirmwarePolicy()
        TargetInfo = {'Manufacturer': manufacturer,
                      'Product': product,
                      'SerialNumber': sn,
                      'OEM_01': oem1,
                      'OEM_02': oem2,
                      'Nonce': nonce}
        policy.SetDeviceTarget(TargetInfo)
        policy.SetDevicePolicy(devicePolicy)
        policy.SerializeToStream(stream=f)
        policy.Print()


def main():
    """Parses command-line parameters using ArgumentParser, passing them to helper functions to perform the requests"""
    parser = argparse.ArgumentParser(description='Firmware Policy Tool')
    subparsers = parser.add_subparsers(required=True, dest='action')

    parser_create = subparsers.add_parser('create', help='Create a firmware policy')
    parser_create.add_argument('PolicyFilename', type=str, help='The name of the new binary policy file to create '
                               '- will not overwrite existing files')
    parser_create.add_argument(
        'Manufacturer', type=str, help='Manufacturer Name, for example, "Contoso Computers, LLC".  '
        'Should match the EV Certificate Subject CN="Manufacturer"')
    parser_create.add_argument('Product', type=str, help='Product Name, for example, "Laptop Foo"')
    parser_create.add_argument(
        'SerialNumber', type=str, help='Serial Number, for example "F0013-000243546-X02".  Should match '
        'SmbiosSystemSerialNumber, SMBIOS System Information (Type 1 Table) -> Serial Number')
    parser_create.add_argument('NonceHex', type=str, help='The nonce in hexadecimal, for example "0x0123456789abcdef"')
    parser_create.add_argument('--OEM1', type=str, default='',
                               help='Optional OEM Field 1, an arbitrary length string, for example "ODM foo"')
    parser_create.add_argument('--OEM2', type=str, default='', help='Optional OEM Field 2, an arbitrary length string')
    parser_create.add_argument('DevicePolicyHex', type=str, help='The device policy in hexadecimal,'
                               ' for example to clear the TPM and delete Secure Boot keys: 0x3')

    parser_print = subparsers.add_parser('parse', help='Parse a firmware policy and print in human readable form')
    parser_print.add_argument('filename', help='Filename to parse and print')

    options = parser.parse_args()

    print('Options: ', options)

    if options.action == 'create':
        nonceInt = int(options.NonceHex, 16)
        devicePolicy = int(options.DevicePolicyHex, 16)
        CreatePolicyFromParameters(options.PolicyFilename, options.Manufacturer,
                                   options.Product, options.SerialNumber, nonceInt,
                                   options.OEM1, options.OEM2, devicePolicy)

    elif options.action == 'parse':
        PrintPolicy(options.filename)


if __name__ == '__main__':
    main()
