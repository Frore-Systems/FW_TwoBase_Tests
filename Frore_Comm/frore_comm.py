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

import json
import logging
from pyftdi.ftdi import Ftdi
from pyftdi.i2c import I2cController, I2cNackError
from io import StringIO
from time import sleep
from threading import Lock
from typing import Literal, NoReturn, Iterable, Optional, Union
import types
from binascii import hexlify
# local modules
from Frore_Comm.frore_utils import *
from pyftdi.usbtools import UsbTools

class FroreComm:
    def __init__(self, serial: Optional[str] = None,
        const: Optional[dict] = None,
        logger: Optional[logging.Logger] = None) -> None:

        self.__logger = logger
        self.__lock = Lock()
        self.__get_ftdi_url(serial)
        if self.url is None:
            self.error('Device not found')
        self.serial = self.url.split(':')[-1].split('/')[0]
        if const is None:
            with open('tests/frore_const.json', 'r') as f:
                const = json.load(f)
        self.const = flatten_dict(const)
        self.scfg = []

    def __get_ftdi_url(self, serial: Optional[str]) -> None:
        UsbTools.flush_cache()
        output = StringIO()
        Ftdi.show_devices(out=output)
        dev_list = output.getvalue().split()
        dev_list = list(filter(lambda a: 'ftdi' in a, dev_list))
        self.debug('Device Available: {}'.format(dev_list))
        output.close()
        if dev_list:
            if serial is None:
                self.url = dev_list[0]
            else:
                # search for device with matching serial number
                url = [item for item in dev_list if serial in item]
                if url:
                    self.url = url[0]
                else:
                    self.url = None
        else:
            self.url = None
        self.debug('Device Selected: {}'.format(self.url))

    def __check_response(self, d: list[int], name: str) \
        -> Union[Literal[True], NoReturn]:
        c = self.const
        size = int.from_bytes(d[3:5], 'little')
        if d[0] != c['COMM_BOM'] or (d[1] & 0x3) != c['COMM_OP_ACK'] or \
            d[2] != c[name] or len(d[5:-1]) != size or d[-1] != c['COMM_EOM']:
            self.error('Command Failure ({})'.format(name))
        return True

    def __zeropad(self, d: list[int], size: int) -> list[int]:
        pad_size = size - len(d)
        if pad_size > 0:
            d += [0]*pad_size
        return d

    def __send_command(self, opcode: list[int], payload: list[int],
        fast_mode: bool = False) -> None:
        c = self.const
        length = list(len(payload).to_bytes(2, 'little'))
        data = [c['COMM_BOM']] + opcode + length + payload + [c['COMM_EOM']]
        #print('Sending command: ' + ' '.join(["%02x" % x for x in data]))
        self.debug('Sending command: {}'.format(list(data)))
        if (fast_mode):
            self.__write_fast(data)
        else:
            self.__write(data)
            sleep(0.002)

    def __read(self, size: int) -> list[int]:
        data = None
        try:
            data = self.port.read(size, True)
            d = list(data) # convert to integer array
            #print('Read data:  ' + ' '.join(["%02x" % x for x in data]))
        except I2cNackError:
            self.port.flush()
            self.error('[Read] I2C NACK Error')
        except ValueError:
            self.error('[Read] Value Error')
        return d

    def __write(self, value: list[int]) -> Union[None, NoReturn]:
        try:
            self.port.write(value, True, True)
        except I2cNackError:
            self.port.flush()
            self.error('[Write] I2C NACK Error')
        except ValueError:
            self.error('[Write] Value Error')

    def __write_fast(self, value: list[int]) -> Union[None, NoReturn]:
        try:
            self.port.write_fast(value)
        except I2cNackError:
            self.port.flush()
            self.error('[Write] I2C NACK Error')
        except ValueError:
            self.error('[Write] Value Error')

    def debug(self, msg: str) -> None:
        if self.__logger != None:
            self.__logger.debug(msg)

    def error(self, msg: str) -> NoReturn:
        if self.__logger != None:
            self.__logger.error(msg)
        raise Exception(msg)

    def info(self, msg: str) -> None:
        if self.__logger != None:
            self.__logger.info(msg)

    def warning(self, msg: str) -> None:
        if self.__logger != None:
            self.__logger.warning(msg)

    def open(self, addr: Optional[int] = None, speed: int = 400000) -> None:
        if addr == None:
            addr = self.const['I2C_ADDRESS']
        self.dev = I2cController()
        self.dev.configure(self.url, frequency=speed)
        self.port = self.dev.get_port(address=addr)
        self.port.write_fast = types.MethodType(write_fast_port, self.port)
        self.port._controller.write_fast = \
            types.MethodType(write_fast_controller, self.port._controller)

    def close(self) -> None:
        self.dev.close()

    def reg16_read(self, index: int, checkresponse: bool = True) -> Union[None, list[int], int]:
        c = self.const
        o = [c['COMM_OP_REG16_READ'], 0]
        s = list(index.to_bytes(2, 'little'))
        p = self.__zeropad(s, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'] + 2)

        if not checkresponse:
            return d
        else:
            if self.__check_response(d, 'COMM_OP_REG16_READ'):
                pidx = c['COMM_RESP_SIZE_DEFAULT'] - 1
                data = int.from_bytes(d[pidx:pidx+2], 'little') # extract 16-bit
                self.debug('Read 16-bit Reg[{:d}] = {:d} (0x{:04x})'
                    .format(index, data, data))
                return data

    def reg16_write(self, index: int, value: int, checkresponse: bool = True) -> Union[None, list[int], int]:
        c = self.const
        o = [c['COMM_OP_REG16_WRITE'], 0]
        s = list(index.to_bytes(2, 'little'))
        v = list(value.to_bytes(2, 'little'))
        p = self.__zeropad(s + v, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        if not checkresponse:
            return d
        else:
            try:
                if self.__check_response(d, 'COMM_OP_REG16_WRITE'):
                    self.debug('Write 16-bit Reg[{:d}] = {:d} (0x{:04x})'
                        .format(index, value, value))
                    return 0
                else:
                    self.error('Write 16-bit Reg[{:d}] failed'.format(index))
            except Exception:
                return -1

    def reg32_read(self, index: int, checkresponse: bool = True) -> Union[None, list[int], int]:
        c = self.const
        o = [c['COMM_OP_REG32_READ'], 0]
        s = list(index.to_bytes(2, 'little'))
        p = self.__zeropad(s, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'] + 4)

        if not checkresponse:
            return d
        else:
            if self.__check_response(d, 'COMM_OP_REG32_READ'):
                pidx = c['COMM_RESP_SIZE_DEFAULT'] - 1
                data = int.from_bytes(d[pidx:pidx+4], 'little') # extract 32-bit
                self.debug('Read 32-bit Reg[{:d}] = {:d} (0x{:08x})'
                    .format(index, data, data))
                return data
            return None

    def reg32_write(self, index: int, value: int, checkresponse: bool = True) -> Union[None, list[int], int]:
        c = self.const
        o = [c['COMM_OP_REG32_WRITE'], 0]
        s = list(index.to_bytes(2, 'little'))
        v = list(value.to_bytes(4, 'little'))
        p = self.__zeropad(s + v, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        if not checkresponse:
            return d
        else:
            if self.__check_response(d, 'COMM_OP_REG32_WRITE'):
                self.debug('Write 32-bit Reg[{:d}] = {:d} (0x{:08x})'
                    .format(index, value, value))

    def ram_read(self, addr: int, size: int, checkresponse: bool = True) -> list[int] | None:
        c = self.const
        o = [c['COMM_OP_RAM_READ'], 0]
        s = list(size.to_bytes(2, 'little'))
        a = list(addr.to_bytes(4, 'little'))
        p = self.__zeropad(s + a, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'] + size)

        if not checkresponse:
            return d
        if self.__check_response(d, 'COMM_OP_RAM_READ'):
            pidx = c['COMM_RESP_SIZE_DEFAULT'] - 1
            data = d[pidx:-1] # extract payload
            self.debug('Read RAM[0x{:08x}][:{}] = {}'
                .format(addr, len(data), data))
            return data
        return None

    def ram_write(self, addr: int, v: list[int], checkresponse: bool = False) -> list[int] | None:
        c = self.const
        size = len(v)
        # enter RAM write mode
        o = [c['COMM_OP_ENTER_RAM_WRITE'], 0]
        s = list(size.to_bytes(2, 'little'))
        a = list(addr.to_bytes(4, 'little'))
        p = self.__zeropad(s + a, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p, True)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        print(d)

        if self.__check_response(d, 'COMM_OP_ENTER_RAM_WRITE'):
            # actual RAM write command
            o = [c['COMM_OP_RAM_WRITE'], 0]
            p = self.__zeropad(s + a, c['COMM_CMD_SIZE_PAYLOAD']) + v
            self.__send_command(o, p, True)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])
            if not checkresponse:
                return d

            if self.__check_response(d, 'COMM_OP_RAM_WRITE'):
                self.debug('Write RAM[0x{:08x}][:{}] = {}'
                    .format(addr, len(v), v))
        return None

    def flash_dread(self, addr: int, size: int, checkresponse: bool = True) -> list[int] | None:
        c = self.const
        if 'COMM_OP_FLASH_DREAD' in c:
            o = [c['COMM_OP_FLASH_DREAD'], 0]
        else:
            o = [22, 0]
        s = list(size.to_bytes(2, 'little'))
        a = list(addr.to_bytes(4, 'little'))
        p = self.__zeropad(s + a, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'] + size)

        if not checkresponse:
            return d

        if self.__check_response(d, 'COMM_OP_FLASH_DREAD'):
            pidx = c['COMM_RESP_SIZE_DEFAULT'] - 1
            data = d[pidx:-1] # extract payload
            self.debug('Read Flash[0x{:08x}][:{}] = {}'
                .format(addr, len(data), data))
            return data
        return None

    def flash_dwrite(self, addr: int, size: int, checksum: int, checkresponse: bool = True) -> list[int] | None:
        c = self.const
        # enter flash write mode
        o = [c['COMM_OP_FLASH_DWRITE'], 0]
        s = list(size.to_bytes(2, 'little'))
        a = list(addr.to_bytes(4, 'little'))
        v = list(checksum.to_bytes(4, 'little'))
        p = self.__zeropad(s + a + v, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            sleep(0.05)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        if not checkresponse:
            return d

        if self.__check_response(d, 'COMM_OP_FLASH_DWRITE'):
            self.debug('Write Flash[0x{:08x}][:{}] = {}'
                .format(addr, len(v), v))
        return None

    def flash_pwrite(self, addr: int, size: int, checksum: int, checkresponse: bool = True) -> list[int] | None:
        c = self.const
        # enter flash write mode
        if 'COMM_OP_FLASH_PWRITE' in c:
            o = [c['COMM_OP_FLASH_PWRITE'], 0]
        else:
            o = [23, 0]
        s = list(size.to_bytes(2, 'little'))
        a = list(addr.to_bytes(4, 'little'))
        v = list(checksum.to_bytes(4, 'little'))
        p = self.__zeropad(s + a + v, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p, True)
            sleep(0.05)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        if not checkresponse:
            return d

        if self.__check_response(d, 'COMM_OP_FLASH_PWRITE'):
            self.debug('Write Flash[0x{:08x}][:{}] = {}'
                .format(addr, len(v), v))
        return None

    def trail_read(self, size: int) -> list[int] | None:
        from Frore_Comm.frore_utils import byte_to_word
        c = self.const
        o = [c['COMM_OP_TRAIL_READ'], 0]
        s = list(size.to_bytes(2, 'little'))
        p = self.__zeropad(s, c['COMM_CMD_SIZE_PAYLOAD'])
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'] + size)
        if self.__check_response(d, 'COMM_OP_TRAIL_READ'):
            pidx = c['COMM_RESP_SIZE_DEFAULT'] - 1
            value = byte_to_word(d[pidx:-1])
            self.debug('Read Trail[:{}] = {}'.format(len(value), value))
            return value
        return None

    def soft_reset(self, checkresponse: bool = False) -> list | None:
        c = self.const
        o = [c['COMM_OP_SOFT_RESET'], 0]
        p = [0]*c['COMM_CMD_SIZE_PAYLOAD']
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])

        if not checkresponse:
            return d
        else:
            self.__check_response(d, 'COMM_OP_SOFT_RESET')
            return None

    def enter_boot(self) -> None:
        c = self.const
        o = [c['COMM_OP_ENTER_BOOT'], 0]
        p = [0]*c['COMM_CMD_SIZE_PAYLOAD']
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])
        self.__check_response(d, 'COMM_OP_ENTER_BOOT')
        sleep(0.1)

    def enter_app(self) -> None:
        c = self.const
        o = [c['COMM_OP_ENTER_APP'], 0]
        p = [0]*c['COMM_CMD_SIZE_PAYLOAD']
        with self.__lock:
            self.__send_command(o, p)
            d = self.__read(c['COMM_RESP_SIZE_DEFAULT'])
        self.__check_response(d, 'COMM_OP_ENTER_APP')
        sleep(0.1)

    def get_info(self, checkresponse: bool = True) -> tuple[str, str, str, str, str, str]:
        c = self.const
        # read product name
        addr = self.reg32_read(c['REG_PRODUCT_NAME_ADDR'], checkresponse)
        data = self.ram_read(addr, c['SYS_PRODUCT_NAME_LEN'])
        prod = bytes(data).decode('ascii').rstrip('\x00')
        # read serial number
        if 'REG_SERIAL_NUMBER' in c:
            data = self.reg32_read(c['REG_SERIAL_NUMBER'])
        else:
            addr = c['FLASH_OTD_START_ADDR'] + c['FLASH_OTD_SIZE'] - 4
            data = byte_to_dword(self.flash_dread(addr, 4))[0]
        sern = '{:02d}.{:02d}.{:05d}'.format(((data >> 24) & 0xFF),
            ((data >> 18) & 0x3F), (data & 0x3FFFF))
        # read HW version
        data = self.reg32_read(c['REG_HARDWARE_VERSION'], checkresponse)
        ver = (data >> 24) & 0xf
        if ver == 2:
            plt = 'TP2'
        elif ver == 3:
            plt = 'PV3'
        elif ver == 4:
            plt = 'BH4'
        else:
            plt = 'XXX'
        cfg = (data >> 16) & 0xFF
        rev = (data >> 8) & 0xFF
        rew = data & 0xFF
        if (rev >> 4) == 0:
            rev = rev & 0x0F
            hw_ver = '{:s}.{:d}.A{:d}.R{:d}'.format(plt, cfg, rev, rew)
        elif (rev >> 4) == 1:
            rev = rev & 0x0F
            hw_ver = '{:s}.{:d}.M{:d}.R{:d}'.format(plt, cfg, rev, rew)
        elif (rev >> 4) == 2:
            rev = rev & 0x0F
            hw_ver = '{:s}.{:d}.B{:d}.R{:d}'.format(plt, cfg, rev, rew)
        else:
            rev = rev & 0x0F
            hw_ver = '{:s}.{:d}.X{:d}.R{:d}'.format(plt, cfg, rev, rew)
        # read FW version
        data = self.reg32_read(c['REG_FIRMWARE_VERSION'], checkresponse)
        fw_ver = '{:d}.{:d}.{:d}.{:d}'.format(((data >> 24) & 0xFF),
            ((data >> 16) & 0xFF), ((data >> 8) & 0xFF), (data & 0xFF))
        # read FBN
        data = self.reg32_read(c['REG_FIRMWARE_BUILD_NUMBER'], checkresponse)
        fbn = '{:d}'.format(data & 0xFFFFFF)
        # read status
        data = self.reg32_read(c['REG_SYSTEM_STATUS'], checkresponse)
        bld = 'BOOT' if data == 0 else 'APP'
        # assemble all info
        info = 'PR-{} SN-{} HW-{} FW-{} BN-{} {}'.format(prod, sern,
            hw_ver, fw_ver, str(fbn).zfill(8), bld)
        self.info(info)
        return prod, sern, hw_ver, fw_ver, fbn, bld

    def get_scfg(self) -> None:
        addr = self.const['FLASH_CFG_START_ADDR']
        if 'REG_STATIC_CONFIG_SIZE' in self.const:
            total_size = self.reg16_read(self.const['REG_STATIC_CONFIG_SIZE'])
        else:
            total_size = 512
        block_size = self.const['COMM_MAX_RX_PAYLOAD_SIZE']
        scfg = []
        counter = 0
        while total_size > 0:
            print(counter)
            size = min(total_size, block_size)
            scfg += self.flash_dread(addr, size)
            addr += size
            total_size -= size
            counter += 1

        print(scfg)
        self.scfg = byte_to_word(scfg)

    def scfg_read(self, offset) -> int:
        if offset < len(self.scfg):
            return self.scfg[offset]
        else:
            return 0

#### FroreComm utility functions ####

def enter_mode(dv: FroreComm, mode: str) -> None:
    c = dv.const
    if dv != None:
        dv.info('Entering {} mode ...'.format(mode.split('_')[-1]))
        dv.reg16_write(c['REG_SYSTEM_MODE_NEXT'], c[mode])
        if c[mode] == c['REGDEF_MODE_SLEEP']: return # skip mode check
        curr_mode = -1
        while curr_mode != c[mode]:
            curr_mode = dv.reg16_read(c['REG_SYSTEM_MODE'])

def run_test(dv: FroreComm, type: str) -> None:
    c = dv.const
    if dv != None:
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
            dv.info('Reading from {} ({} bytes) ...'
                .format(limit_string(infile, 20), len(data)))
        else:
            dv.error('Invalid binary file')
    else:
        dv.error('Binary file does not exist')

    # get constant definitions
    c = dv.const
    header_size = 4*c['SYS_PKG_DESCRIPTOR_SIZE']
    type_offset = 4*c['SYS_PKG_TYPE_OFFSET']
    addr_offset = 4*c['SYS_PKG_ADDR_OFFSET']
    size_offset = 4*c['SYS_PKG_SIZE_OFFSET']
    rawsize_offset = 4*c['SYS_PKG_RAWSIZE_OFFSET']
    checksum_offset = 4*c['SYS_PKG_CHECKSUM_OFFSET']
    bintype_mask = c['SYS_PKG_BINTYPE_MASK']
    bintype_raw = c['SYS_PKG_BINTYPE_RAW']
    bintype_enc1 = c['SYS_PKG_BINTYPE_ENC1']
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
            # update OTD segment
            verif_type = pkg_type & verif_mask
            addr = c['FLASH_OTD_START_ADDR']
            size = c['FLASH_OTD_SIZE']
            # read existing OTD segment
            otd = dv.flash_dread(addr, size)
            if verif_type == verif_fletcher32:
                otd[0:4] = dword_to_byte([(pkg_type >> 8) & 0xFF]) # AppCfg
                otd[4:8] = dword_to_byte([c['FLASH_APP_START_ADDR']]) # AppAddr
                otd[8:12] = dword_to_byte([raw_size]) # AppSize
                reflash_section(dv, addr, otd, 'DATA')
            elif verif_type == verif_bypass:
                otd[0:4] = [0xFF, 0xFF, 0xFF, 0xFF] # AppCfg
                reflash_section(dv, addr, otd, 'DATA')

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
            dv.info('S{} B{} ({}) into RAM @0x{:08x}'
                .format(f_cnt+1, r_cnt+1, b_size, r_addr))
            data = data[b_size:]
            r_addr += b_size
            r_size -= b_size
            r_cnt += 1
        if type == 'PROG':
            dv.flash_pwrite(f_addr, s_size, checksum)
        elif type == 'DATA':
            dv.flash_dwrite(f_addr, s_size, checksum)
        dv.info('S{} ({}, 0x{:08x}) into FLASH @0x{:08x}'
            .format(f_cnt+1, s_size, checksum, f_addr))
        f_addr += s_size
        f_size -= s_size
        f_cnt += 1

def reflash_sern(dv: FroreComm, sern: int) -> None:
    if dv != None:
        c = dv.const
        addr = c['FLASH_OTD_START_ADDR']
        size = c['FLASH_OTD_SIZE']
        otd = dv.flash_dread(addr, c['FLASH_OTD_SIZE'])
        otd[-4:] = dword_to_byte([sern]) # SerialNumber
        reflash_section(dv, addr, otd, 'DATA')

# PyFTDI function override
def write_fast_port(self, out: Union[bytes, bytearray, Iterable[int]],
    relax: bool = True, start: bool = True) -> None:

    return self._controller.write_fast(
        self._address+self._shift if start else None, out, True)

# PyFTDI function override
def write_fast_controller(self, address: Optional[int],
    out: Union[bytes, bytearray, Iterable[int]], relax: bool = True) -> None:

    self.validate_address(address)
    if address is None:
        i2caddress = None
    else:
        i2caddress = (address << 1) & self.HIGH

    if not isinstance(out, bytearray):
        out = bytearray(out)
    if not out:
        return

    self.log.debug('- write %d byte(s): %s', len(out), hexlify(out).decode())

    start_duration_1 = 1
    start_duration_2 = 1

    stop_duration_1 = 1
    stop_duration_2 = 1
    stop_duration_3 = 1

    FASTWRITE_READ_ACK = 1

    bytesToRead = 0
    bytesToTransfer = (int)(((len(out)*8) + 7) / 8)
    if FASTWRITE_READ_ACK:
        sizeTotal = (bytesToTransfer * (6+5)) + 11 + \
            (start_duration_1+start_duration_2+1)*3 + \
            (stop_duration_1+stop_duration_2+stop_duration_3+1)*3
    else:
        sizeTotal = (bytesToTransfer * (6)) + 11 + \
            (start_duration_1+start_duration_2+1)*3 + \
            (stop_duration_1+stop_duration_2+stop_duration_3+1)*3

    # start sequence
    cmd = bytearray()
    # SCL high, SDA high
    for j in range(start_duration_1):
        cmd.append(0x80)
        cmd.append(0x03)
        cmd.append(0x13)
    # SCL high, SDA low 
    for j in range(start_duration_2):
        cmd.append(0x80)
        cmd.append(0x01)
        cmd.append(0x13)
    # SCL low, SDA low
    cmd.append(0x80)
    cmd.append(0x00)
    cmd.append(0x13)

    # address
    cmd.append(0x80)
    cmd.append(0x02)
    cmd.append(0x13)

    cmd.append(0x13)
    cmd.append(0x07)
    cmd.append(i2caddress)

    # ack address
    if FASTWRITE_READ_ACK:
        cmd.append(0x80)
        cmd.append(0x00)
        cmd.append(0x11)

        cmd.append(0x22)
        cmd.append(0x00)
        bytesToRead += 1

    # data
    for byte in out:
        cmd.append(0x80)
        cmd.append(0x02)
        cmd.append(0x13)

        cmd.append(0x13)
        cmd.append(0x07)
        cmd.append(byte)

        if FASTWRITE_READ_ACK:
            cmd.append(0x80)
            cmd.append(0x00)
            cmd.append(0x11)

            cmd.append(0x22)
            cmd.append(0x00)
            bytesToRead += 1
    
    # stop bit
    for i in range(stop_duration_1):
        cmd.append(0x80)
        cmd.append(0x00)
        cmd.append(0x13)

    for i in range(stop_duration_2):
        cmd.append(0x80)
        cmd.append(0x01)
        cmd.append(0x13)

    for i in range(stop_duration_3):
        cmd.append(0x80)
        cmd.append(0x03)
        cmd.append(0x13)

    cmd.append(0x80)
    cmd.append(0x03)
    cmd.append(0x10)

    self._ftdi.write_data(cmd)

    # read ack
    if FASTWRITE_READ_ACK:
        acks = self._ftdi.read_data_bytes(bytesToRead, 4)

if __name__ == '__main__':
    from tests.utils import *
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    sh = logging.StreamHandler()
    logger.addHandler(sh)
    dv = FroreComm(logger=logger)
    dv.open()
    dv.get_info() # read board info
    reflash_pkgfile(dv, "tests/BH4.11.M1.R0_2.6.0.8_00001084_app.pkg")
