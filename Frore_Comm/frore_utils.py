#------------------------------------------------------------------------------
# Copyright (c) 2024-2025 Frore Systems Incorporated. All rights reserved.
#
# This document contains information that is proprietary to Frore Systems
# Incorporated. This document shall not be modified and/or distributed
# without the written permission of Frore Systems Incorporated.
#
# Frore Systems Incorporated
# 2333 Zanker Road
# San Jose, CA 95131
#------------------------------------------------------------------------------

import os
import json
import platform
import logging
from cryptography.fernet import Fernet
from time import sleep
import sys

#### Generic utility functions ####

def byte_to_word(x: list[int]) -> list[int]:
    l = len(x)
    x.extend([0]*(l%1))
    return [x[i]+(x[i+1]<<8) for i in range(0, l, 2)]

def word_to_byte(x: list[int]) -> list[int]:
    z = [(y&0xFF, (y>>8)&0xFF) for y in x]
    return [m for n in z for m in n]

def byte_to_dword(x: list[int]) -> list[int]:
    l = len(x)
    x.extend([0]*((4-l)&0x3))
    return [x[i]+(x[i+1]<<8)+(x[i+2]<<16)+(x[i+3]<<24) for i in range(0, l, 4)]

def dword_to_byte(x: list[int]) -> list[int]:
    z = [(y&0xFF, (y>>8)&0xFF, (y>>16)&0xFF, (y>>24)&0xFF) for y in x]
    return [m for n in z for m in n]

def word_to_dword(x: list[int]) -> list[int]:
    l = len(x)
    x.extend([0]*(l%1))
    return [x[i]+(x[i+1]<<16) for i in range(0, l, 2)]

def dword_to_word(x: list[int]) -> list[int]:
    z = [(y&0xFFFF, (y>>16)&0xFFFF) for y in x]
    return [m for n in z for m in n]

def print_byte(x: list[int], idx: int) -> None:
    if len(x) == 0: return
    print('{:6d} bytes  :'.format(len(x)), end=' ')
    x = x[:] if idx == 0 else x[:idx]
    for i in range(len(x)):
        print('0x{:02x}'.format(x[i]), end=' ')
    print('') if idx == 0 else print('...')

def print_word(x: list[int], idx: int) -> None:
    if len(x) == 0: return
    print('{:6d} words  :'.format(len(x)), end=' ')
    x = x[:] if idx == 0 else x[:idx]
    for i in range(len(x)):
        print('0x{:04x}'.format(x[i]), end=' ')
    print('') if idx == 0 else print('...')

def print_dword(x: list[int], idx: int) -> None:
    if len(x) == 0: return
    print('{:6d} dwords :'.format(len(x)), end=' ')
    x = x[:] if idx == 0 else x[:idx]
    for i in range(len(x)):
        print('0x{:08x}'.format(x[i]), end=' ')
    print('') if idx == 0 else print('...')

def read_bin(f: str) -> list[int]:
    with open(f, mode='rb') as fp:
        y = [x for x in bytearray(fp.read())]
    return y

def write_bin(f: str, data: list[int]) -> None:
    out = bytes(data)
    with open(f, mode='wb') as fp:
        fp.write(out)

def fletcher32(data: list[int], size: int) -> int:
    x0 = 0; x1 = 0
    data = byte_to_word(data) # convert to 16-bit array
    size = size // 2
    for i in range(0, size):
        x0 += data[i]
        x1 += x0
        x0 = (x0 & 0x0000FFFF) + (x0 >> 16)
        x1 = (x1 & 0x0000FFFF) + (x1 >> 16)
    x0 = (x0 & 0x0000FFFF) + (x0 >> 16)
    x1 = (x1 & 0x0000FFFF) + (x1 >> 16)
    y = ((x1 & 0x0000FFFF) << 16) | (x0 & 0x0000FFFF)
    return y

def MX(z: int, y: int, s: int, k: int) -> int:
    return (((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((s^y)+(k^z))

def extract_dict(data: dict[str, int], type: str) -> dict[str, int]:
    d = {}
    for k in data.keys():
        if type in k:
            d |= {k: data[k]}
        if type == 'SCFG_' and '_' not in k: # constants not in snake case
            d |= {k: data[k]}
    return d

def invert_dict(data: dict[str, int], type: str) -> dict[int, str]:
    d = {}
    for k in data.keys():
        if type in k:
            d |= {k: data[k]}
    return {v: k for k, v in d.items()}

def flatten_dict(data: [dict[str, dict[str, int]]]) -> dict[str, int]:
    d = {}
    for outer_key, inner_dict in data.items():
        if isinstance(inner_dict, dict):
            d.update(inner_dict)
        else:
            d[outer_key] = inner_dict
    return d

def limit_string(data: str, size: int) -> str:
    if len(data) > size:
        d = data[:10] + '...' + data[-(size-10):]
    else:
        d = data
    return d

def stm_cli_get_command() -> str:
    build_os = sys.platform
    cmd = ''
    if build_os == 'win32':
        cmd = 'STM32_Programmer_CLI.exe'
    elif build_os == 'linux':
        cmd = 'STM32_Programmer_CLI'
    elif build_os == 'darwin':
        cmd = '/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/MacOs/bin/STM32_Programmer_CLI'
    return cmd

def stm_cli_reset() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --start'
    os.system(command)
    sleep(0.5)

def stm_cli_erase_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --optionbytes RDP=0xAA nBOOT_SEL=0'
    os.system(command)
    sleep(0.5)
    command = f'{cmd} -c port=SWD -e all'
    os.system(command)
    sleep(0.5)

def stm_cli_unlock_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --optionbytes RDP=0xAA nBOOT_SEL=0'
    os.system(command)
    sleep(0.5)

def stm_cli_lock_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --optionbytes RDP=0xBB nBOOT_SEL=0'
    os.system(command)
    sleep(0.5)

def stm_cli_reflash_binfile(infile: str, addr: int) -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst -w {infile} {addr}'
    os.system(command)
    sleep(0.5)

def stm_cli_reflash_hexfile(infile: str) -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst -w {infile}'
    os.system(command)
    sleep(0.5)

def stm_cli_reflash_pkgfile(logger: logging.Logger, dev_const: dict[str, int], \
    infile: str) -> None:
    COMMON_KEY = b'AUmC0J8PViy_2taeWbcRy8dItIXwbmX6KWjxfbHKZHE='
    # read from PKG file
    data = []
    if os.path.isfile(infile):
        data = read_bin(infile)
        if data is not None:
            logger.info('Reading from {} ({} bytes) ...'.format(infile, len(data)))
        else:
            logger.error('Invalid binary file')
    else:
        logger.error('Binary file does not exist')

    # get constant definitions
    c = dev_const
    header_size = 4*c['SYS_PKG_DESCRIPTOR_SIZE']
    type_offset = 4*c['SYS_PKG_TYPE_OFFSET']
    addr_offset = 4*c['SYS_PKG_ADDR_OFFSET']
    size_offset = 4*c['SYS_PKG_SIZE_OFFSET']
    rawsize_offset = 4*c['SYS_PKG_RAWSIZE_OFFSET']
    checksum_offset = 4*c['SYS_PKG_CHECKSUM_OFFSET']
    bintype_mask = c['SYS_PKG_BINTYPE_MASK']
    bintype_raw = c['SYS_PKG_BINTYPE_RAW']
    bintype_enc1 = c['SYS_PKG_BINTYPE_ENC1']
    bintype_enc2 = c['SYS_PKG_BINTYPE_ENC2']
    verif_mask = c['SYS_PKG_VERIF_MASK']
    verif_bypass = c['SYS_PKG_VERIF_BYPASS']
    verif_fletcher32 = c['SYS_PKG_VERIF_FLETCHER32']

    while len(data):
        # extract PKG info
        header = data[:header_size] # extract header
        pkg_type = byte_to_dword(header[type_offset:type_offset+4])[0]
        bin_addr = byte_to_dword(header[addr_offset:addr_offset+4])[0]
        bin_size = byte_to_dword(header[size_offset:size_offset+4])[0]
        raw_size = byte_to_dword(header[rawsize_offset:rawsize_offset+4])[0]
        checksum = byte_to_dword(header[checksum_offset:checksum_offset+4])[0]
        bin_data = data[header_size:header_size+bin_size]
        data = data[header_size+bin_size:]
        logger.info('PKG Info: Header ({} bytes), Body ({} bytes)'
            .format(len(header), len(bin_data)))

        if bin_data is not None:
            # create a temporary binary
            tempfile = infile.split('.pkg')[0]
            tempfile += '_0x{:08x}.bin'.format(bin_addr)
            write_bin(tempfile, bin_data)
            # decrypt file if necessary
            bin_type = pkg_type & bintype_mask
            if bin_type == bintype_enc2:
                enc_data = read_bin(tempfile)
                fer = Fernet(COMMON_KEY)
                dec = fer.decrypt(bytes(enc_data))
                dec_data = [x for x in bytearray(dec)]
                write_bin(tempfile, dec_data)
            # binary type
            stm_cli_reflash_binfile(tempfile, bin_addr)

if __name__ == '__main__':

    data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    # cksum = fletcher32(data, 16)
    data = [1, *[0]*251] + [1, 2, 3, 4]
    data = [0] * 16
    print(list(data))
    cksum = fletcher32(data, len(data))
    print(cksum)
    # data = read_bin('app.pkg')
    # block_byte = data[:16]
    #
    # # test data type conversion
    # print_byte(block_byte, 0)
    #
    # block_word = byte_to_word(block_byte)
    # print_word(block_word, 0)
    #
    # block_dword = word_to_dword(block_word)
    # print_dword(block_dword, 0)
    #
    # block_dword = byte_to_dword(block_byte)
    # print_dword(block_dword, 0)
