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
from time import sleep
from frore_comm import FroreComm

# FIXME: redundant definitions in const.h
SYS_PKG_DESCRIPTOR_SIZE =   32 # in double words (128 bytes, 1024 bits)
SYS_PKG_TYPE_OFFSET =       0 # PKG_TYPE field offset
SYS_PKG_TYPE_LENGTH =       1 # PKG_TYPE field length
SYS_PKG_DEFAULT =           0x00000000 # PKGTYPE field default value
SYS_PKG_BINTYPE_MASK =      0x000000FF # BINTYPE subfield mask
SYS_PKG_BINTYPE_RAW =       0x00000001 # raw binary
SYS_PKG_BINTYPE_ENC1 =      0x00000002 # encrypted binary (custom key)
SYS_PKG_BINTYPE_ENC2 =      0x00000003 # encrypted binary (common key)
SYS_PKG_VERIF_MASK =        0x0000FF00 # VERIF subfield
SYS_PKG_VERIF_BYPASS =      0x00000000 # bypass
SYS_PKG_VERIF_FLETCHER32 =  0x00000100 # 32-bit checksum
SYS_PKG_ADDR_OFFSET =       1 # start address in FLASH
SYS_PKG_ADDR_LENGTH =       1
SYS_PKG_SIZE_OFFSET =       2 # attached binary size in bytes
SYS_PKG_SIZE_LENGTH =       1
SYS_PKG_RAWSIZE_OFFSET =    3 # raw binary size in bytes
SYS_PKG_RAWSIZE_LENGTH =    1
SYS_PKG_CHECKSUM_OFFSET =   4 # checksum appended to binary
SYS_PKG_CHECKSUM_LENGTH =   1 # may change based on verification type
SYS_PKG_RESERVED_OFFSET =   5 # reserved for future use
SYS_PKG_RESERVED_LENGTH =   27

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

#### FroreComm utility functions ####

def enter_mode(dv: FroreComm, mode: str) -> None:
    c = dv.const
    if dv != None:
        dv.info('Entering {} mode'.format(mode.split('_')[-1]))
        dv.reg16_write(c['REG_SYSTEM_MODE_NEXT'], c[mode])
        if c[mode] == c['REGDEF_MODE_SLEEP']: return # skip mode check
        curr_mode = -1
        while curr_mode != c[mode]:
            curr_mode = dv.reg16_read(c['REG_SYSTEM_MODE'])

def run_test(dv: FroreComm, type: str) -> None:
    c = dv.const
    if dv != None:
        dv.info('Running {} test'.format(type.split('_')[-1]))
        dv.reg16_write(c['REG_TEST_TYPE'], c[type])
        dv.reg16_write(c['REG_SYSTEM_MODE_NEXT'], c['REGDEF_MODE_TEST'])
        curr_type = -1
        while curr_type != c['REGDEF_TEST_IDLE']:
            curr_type = dv.reg16_read(c['REG_TEST_TYPE'])

def reflash_pkgfile(dv: FroreComm, infile: str) -> None:
    # read from PKG file
    if os.path.isfile(infile):
        data = read_bin(infile)
        if data is not None:
            dv.info('Read from {} ({} bytes) ...'.format(infile, len(data)))
        else:
            dv.error('Invalid binary file')
    else:
        dv.error('Binary file does not exist')
    # get constant definitions
    c = dv.const
    header_size = 4*SYS_PKG_DESCRIPTOR_SIZE
    type_offset = 4*SYS_PKG_TYPE_OFFSET
    addr_offset = 4*SYS_PKG_ADDR_OFFSET
    size_offset = 4*SYS_PKG_SIZE_OFFSET
    rawsize_offset = 4*SYS_PKG_RAWSIZE_OFFSET
    checksum_offset = 4*SYS_PKG_CHECKSUM_OFFSET
    bintype_mask = SYS_PKG_BINTYPE_MASK
    bintype_raw = SYS_PKG_BINTYPE_RAW
    bintype_enc1 = SYS_PKG_BINTYPE_ENC1
    verif_mask = SYS_PKG_VERIF_MASK
    verif_bypass = SYS_PKG_VERIF_BYPASS
    verif_fletcher32 = SYS_PKG_VERIF_FLETCHER32

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
        dv.info('PKG Info: Header ({} bytes), Body ({} bytes)'
            .format(len(header), len(bin_data)))

        # binary type
        bin_type = pkg_type & bintype_mask
        if bin_type == bintype_raw:
            # write data section
            reflash_section(dv, bin_addr, bin_data, 'DATA')
        elif bin_type == bintype_enc1:
            # write program section
            reflash_section(dv, bin_addr, bin_data, 'PROG')
            # update OTD section
            verif_type = pkg_type & verif_mask
            bin_addr = c['FLASH_OTD_START_ADDR']
            if verif_type == verif_fletcher32:
                # write APP config
                app_cfg = (pkg_type >> 8) & 0xFF
                otd = [0] * c['FLASH_OTD_SIZE']
                otd[0:4] = dword_to_byte([app_cfg])
                otd[4:8] = dword_to_byte([c['FLASH_APP_START_ADDR']])
                otd[8:12] = dword_to_byte([raw_size])
                reflash_section(dv, bin_addr, otd, 'DATA')
            else:
                # indicate verification bypass
                otd = [0xFF] * 256
                reflash_section(dv, bin_addr, otd, 'DATA')

def reflash_section(dv: FroreComm, addr: int, data: list[int],
    type: str) -> None:
    # get constant definitions
    c = dv.const
    page_size = c['FLASH_WRITE_PAGE_SIZE']
    ram_addr = dv.reg32_read(c['REG_FLASH_COPY_ADDR'])
    ram_size = c['COMM_MAX_RX_PAYLOAD_SIZE']

    if len(data) < ram_size:
        data += [0]*(ram_size-len(data))

    # write FLASH data section
    f_addr = addr
    f_size = len(data)
    f_cnt = 0
    while f_size:
        r_addr = ram_addr
        r_size = min(f_size, page_size)
        checksum = fletcher32(data[:r_size], r_size)
        s_size = r_size
        r_cnt = 0
        while r_size:
            b_size = min(r_size, ram_size)
            dv.ram_write(r_addr, data[:b_size])
            dv.info('Writing Section {} Block {} ({}) into RAM @0x{:08x} ...'
                .format(f_cnt+1, r_cnt+1, b_size, r_addr))
            data = data[b_size:]
            r_addr += b_size
            r_size -= b_size
            r_cnt += 1
        if type == 'PROG':
            dv.flash_pwrite(f_addr, s_size, checksum)
        elif type == 'DATA':
            dv.flash_dwrite(f_addr, s_size, checksum)
        dv.info('Writing Section {} ({}, 0x{:08x}) into FLASH @0x{:08x} ...'
            .format(f_cnt+1, s_size, checksum, f_addr))
        f_addr += s_size
        f_size -= s_size
        f_cnt += 1

def stm_cli_get_command() -> str:
    build_os = platform.machine()
    if build_os == 'AMD64':
        cmd = 'STM32_Programmer_CLI.exe'
    elif build_os == 'arm64': # FIXME: not yet supported
        cmd = 'ls'
    return cmd

def stm_cli_reset() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --start'
    os.system(command)

def stm_cli_erase_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD -e all'
    os.system(command)

def stm_cli_unlock_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --optionbytes RDP=0xAA'
    os.system(command)

def stm_cli_lock_flash() -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst --optionbytes RDP=0xBB nBOOT_SEL=0'
    os.system(command)

def stm_cli_reflash_binfile(infile: str, addr: int) -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst -w {infile} {addr}'
    os.system(command)

def stm_cli_reflash_hexfile(infile: str) -> None:
    cmd = stm_cli_get_command()
    command = f'{cmd} -c port=SWD reset=HWrst -w {infile}'
    os.system(command)

def stm_cli_reflash_pkgfile(logger: logging.Logger, infile: str) -> None:
    # read from PKG file
    if os.path.isfile(infile):
        data = read_bin(infile)
        if data is not None:
            logger.info('Read from {} ({} bytes) ...'.format(infile, len(data)))
        else:
            logger.error('Invalid binary file')
    else:
        logger.error('Binary file does not exist')
    # get constant definitions
    header_size = 4*SYS_PKG_DESCRIPTOR_SIZE
    type_offset = 4*SYS_PKG_TYPE_OFFSET
    addr_offset = 4*SYS_PKG_ADDR_OFFSET
    size_offset = 4*SYS_PKG_SIZE_OFFSET
    rawsize_offset = 4*SYS_PKG_RAWSIZE_OFFSET
    checksum_offset = 4*SYS_PKG_CHECKSUM_OFFSET
    bintype_mask = SYS_PKG_BINTYPE_MASK
    bintype_raw = SYS_PKG_BINTYPE_RAW
    bintype_enc1 = SYS_PKG_BINTYPE_ENC1
    verif_mask = SYS_PKG_VERIF_MASK
    verif_bypass = SYS_PKG_VERIF_BYPASS
    verif_fletcher32 = SYS_PKG_VERIF_FLETCHER32

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

        # binary type
        bin_type = pkg_type & bintype_mask
        if bin_type == bintype_raw:
            if bin_data is not None:
                tempfile = infile.split('.pkg')[0]
                tempfile += '_0x{:08x}.bin'.format(bin_addr)
                write_bin(tempfile, bin_data)
                stm_cli_reflash_binfile(tempfile, bin_addr)

if __name__ == '__main__':

    data = read_bin('app.pkg')
    block_byte = data[:16]

    # test data type conversion
    print_byte(block_byte, 0)

    block_word = byte_to_word(block_byte)
    print_word(block_word, 0)

    block_dword = word_to_dword(block_word)
    print_dword(block_dword, 0)

    block_dword = byte_to_dword(block_byte)
    print_dword(block_dword, 0)
