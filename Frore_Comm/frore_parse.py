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

import json, csv
from datetime import datetime
from typing import Optional, Union
from frore_comm import FroreComm
from frore_utils import *
from threading import Lock

column = 0 # global variable to track memory dump column number
parse_count = 0 # gloabl variable to track parsing counts

BOOST_PARAM_LEN = 5 # number of boost parameters
TILE_PARAM_LEN = 7 # number of tile parameters
TEMP_PARAM_LEN = 2 # number of temperature parameters
trail_buffer = []

def reset_parse_count() -> None:
    global parse_count
    parse_count = 0

def reset_buffer() -> None:
    global trail_buffer
    trail_buffer = []

def reset_event_trail() -> None:
    reset_parse_count()
    reset_buffer()

def get_message(buffer: list[int]) \
    -> Union[tuple[None, list[int]], tuple[list[int], list[int]]]:
    """
    Extract one valid Event Trail message in the buffer
    Discard invalid values
    """
    if buffer == [] or len(buffer) < 3: # not enough data in the buffer
        return None, buffer

    length = 2 + buffer[1] # get the length of 1st message
    if length <= len(buffer):
        return buffer[:length], buffer[length:] # split 1st message
    else:
        return None, buffer # no message yet, return buffer as-is

def get_event_trail_fields(num_bch: int, num_tch: int, max_size: int) \
    -> dict[str, int]:
    """
    Construct dictionary for CSV format
    """
    fields: dict[str, int] = {}
    cidx = 0
    fields['EventTrailType'] = cidx
    cidx += 1
    fields['Timestamp'] = cidx
    cidx += 1
    fields['MessageCode'] = cidx
    cidx += 1
    fields['FrameNumber'] = cidx
    cidx += 1
    fields['Reserved1'] = cidx
    cidx += 1
    fields['Reserved2'] = cidx
    cidx += 1
    fields['Reserved3'] = cidx
    cidx += 1
    fields['Reserved4'] = cidx
    cidx += 1
    fields['Reserved5'] = cidx
    cidx += 1
    fields['Reserved6'] = cidx
    cidx += 1
    fields['Reserved7'] = cidx
    cidx += 1
    fields['Reserved8'] = cidx
    cidx += 1
    fields['HostTemperature'] = cidx
    for i in range(0, num_bch):
        cidx += 1
        fields['VbstSet{}'.format(i+1)] = cidx
    for i in range(0, num_bch):
        cidx += 1
        fields['VbstRead{}'.format(i+1)] = cidx
    for i in range(0, num_bch):
        cidx += 1
        fields['Hcsa{}'.format(i+1)] = cidx
    for i in range(0, num_bch):
        cidx += 1
        fields['BoostPower{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['Frequency{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['DutyCycle{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['Vpzt{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['Lcsa{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['Power{}'.format(i+1)] = cidx
    for i in range(0, num_tch):
        cidx += 1
        fields['Temperature{}'.format(i+1)] = cidx
    cidx += 1
    fields['BchMask'] = cidx
    cidx += 1
    fields['TchMask'] = cidx
    cidx += 1
    fields['AdcMask'] = cidx
    cidx += 1
    fields['AdcCount'] = cidx
    for i in range(0, max_size):
        cidx += 1
        fields['AdcData{:03d}'.format(i+1)] = cidx
    return fields

def parse_message_mem(outfile: str, message: Optional[list[list[int]]]) -> None:
    """
    Convert one or more Event Trail messages in memory dump format
    """
    global column

    if message == None:
        return

    msg = [x for xs in message for x in xs] # flatten messages into one list
    data = word_to_byte(msg)
    with open(outfile, 'a') as f:
        for byte in data:
            if (column % 32) == 31:
                f.write('{:02X}\n'.format(byte))
                column = 0
            else:
                f.write('{:02X} '.format(byte))
                column += 1
    return

def parse_message_json(dv: FroreComm, outfile: str, num_bch: int, num_tch: int,
    message: list[list[int]]) -> None:
    """
    Parse one or more Event Trail messages in JSON format
    """
    c = dv.const
    etp_inv = invert_dict(c, 'ETP_')
    evc_inv = invert_dict(c, 'EVC_')
    erc_inv = invert_dict(c, 'ERC_')

    log = json.loads('{}')
    log['DateTime'] = '{}'.format(datetime.now())
    log['EventTrail'] = []

    for msg in message:
        opcode = msg[0]
        record = '{}'
        record = json.loads(record)
        if opcode in etp_inv:
            record['EventTrailType'] = "{}".format(etp_inv[msg[0]])
        else:
            dv.error("[Trail Parse] Invalid Trail Type")
        # parse ETP_EVENT payload
        if (opcode == c['ETP_EVENT']):
            record['Timestamp'] = '{:d}'.format((msg[3]<<16) + msg[2])
            record['MessageCode'] = '{}'.format(evc_inv[msg[4]])
        # parse ETP_ERROR payload
        elif (opcode == c['ETP_ERROR']):
            record['Timestamp'] = '{:d}'.format((msg[3]<<16) + msg[2])
            record['MessageCode'] = '{}'.format(erc_inv[msg[4]])
        # parse ETP_FRAME payload
        elif (opcode == c['ETP_FRAME']):
            record['Timestamp'] = '{:d}'.format((msg[3]<<16) + msg[2])
            record['FrameNumber'] = '{:d}'.format(msg[4])
            record['Reserved1'] = '{:d}'.format(msg[5])
            record['Reserved2'] = '{:d}'.format(msg[6])
            record['Reserved3'] = '{:d}'.format(msg[7])
            record['Reserved4'] = '{:d}'.format(msg[8])
            record['Reserved5'] = '{:d}'.format(msg[9])
            record['Reserved6'] = '{:d}'.format(msg[10])
            record['Reserved7'] = '{:d}'.format(msg[11])
            record['Reserved8'] = '{:d}'.format(msg[12])
            record['HostTemperature'] = '{:0.3f}'.format(msg[13]/100.0)
            bch_mask = msg[14]
            tch_mask = msg[15]
            record['BoostChannelMask'] = '0x{:02x}'.format(bch_mask)
            log_bch_mask = msg[16]
            log_tch_mask = msg[17]
            log_adc_mask = msg[18]
            log_adc_count = msg[19]
            num_idx = 20
            param = msg[num_idx:]
            for i in range(0, num_bch):
                if (bch_mask & (1<<i)):
                    value = param[BOOST_PARAM_LEN*i:]
                    boost = 'Boost{}'.format(str(value[0]+1)) # boost ID
                    record[boost] = {}
                    record[boost]['Channel'] = '{:d}'.format(value[0])
                    record[boost]['VbstSet'] = '{:0.3f}'.format(value[1]/1000.0)
                    record[boost]['VbstRead'] = '{:0.3f}'.format(value[2]/1000.0)
                    record[boost]['Hcsa'] = '{:0.3f}'.format(value[3]/10.0)
                    record[boost]['Power'] = '{:0.3f}'.format(value[4]/1000.0)
            record['TileChannelMask'] = '0x{:02x}'.format(tch_mask)
            num_idx += num_bch * BOOST_PARAM_LEN
            param = msg[num_idx:]
            for i in range(0, num_tch):
                if (tch_mask & (1<<i)):
                    value = param[TILE_PARAM_LEN*i:]
                    tile = 'Tile{}'.format(str(value[0]+1)) # tile ID
                    record[tile] = {}
                    record[tile]['Channel'] = '{:d}'.format(value[0])
                    record[tile]['Frequency'] = '{:0.3f}'.format(value[1]/1000.0)
                    record[tile]['DutyCycle'] = '{:0.3f}'.format(value[2]/10.0)
                    record[tile]['Vpzt'] = '{:0.3f}'.format(value[3]/100.0)
                    record[tile]['Lcsa'] = '{:0.3f}'.format(value[4]/10.0)
                    record[tile]['Power'] = '{:0.3f}'.format(value[5]/1000.0)
                    record[tile]['Temperature'] = '{:0.3f}'.format(value[6]/100.0)
            num_idx += num_tch * TILE_PARAM_LEN
            param = msg[num_idx:]
            if log_adc_count > 0:
                record['BchMask'] = '0x{:02x}'.format(log_bch_mask)
                record['TchMask'] = '0x{:02x}'.format(log_tch_mask)
                record['AdcMask'] = '0x{:02x}'.format(log_adc_mask)
                record['AdcCount'] = '{:d}'.format(log_adc_count)
                record['AdcData'] = '{}'.format(param[:log_adc_count])
        log['EventTrail'].append(record)

    with open(outfile, 'a') as f:
        text = json.dumps(log, indent=4)
        f.write(text)
        f.write(',\n')

    return

def parse_message_csv(dv: FroreComm, outfile: str, num_bch: int, num_tch: int,
    field: dict[str, int], message: list[list[int]]) -> None:
    """
    Parse one or more Event Trail messages in CSV format
    """
    global parse_count
    c = dv.const
    etp_inv = invert_dict(c, 'ETP_')
    evc_inv = invert_dict(c, 'EVC_')
    erc_inv = invert_dict(c, 'ERC_')

    block: list[list[str]] = []
    for msg in message:
        opcode = msg[0]
        record = ['' for _ in range(len(field))]
        if opcode in etp_inv:
            idx = field['EventTrailType']
            record[idx] = etp_inv[msg[0]]
        else:
            dv.error("[Trail Parse] Invalid Trail Type")
        # parse ETP_EVENT payload
        if (opcode == c['ETP_EVENT']):
            idx = field['Timestamp']
            record[idx] = '{:d}'.format((msg[3]<<16) + msg[2])
            idx = field['MessageCode']
            record[idx] = '{}'.format(evc_inv[msg[4]])
        # parse ETP_ERROR payload
        elif (opcode == c['ETP_ERROR']):
            idx = field['Timestamp']
            record[idx] = '{:d}'.format((msg[3]<<16) + msg[2])
            idx = field['MessageCode']
            record[idx] = '{}'.format(erc_inv[msg[4]])
        # parse ETP_FRAME payload
        elif (opcode == c['ETP_FRAME']):
            idx = field['Timestamp']
            record[idx] = '{:d}'.format((msg[3]<<16) + msg[2])
            idx = field['FrameNumber']
            record[idx] = '{:d}'.format(msg[4])
            idx = field['Reserved1']
            record[idx] = '{:d}'.format(msg[5])
            idx = field['Reserved2']
            record[idx] = '{:d}'.format(msg[6])
            idx = field['Reserved3']
            record[idx] = '{:d}'.format(msg[7])
            idx = field['Reserved4']
            record[idx] = '{:d}'.format(msg[8])
            idx = field['Reserved5']
            record[idx] = '{:d}'.format(msg[9])
            idx = field['Reserved6']
            record[idx] = '{:d}'.format(msg[10])
            idx = field['Reserved7']
            record[idx] = '{:d}'.format(msg[11])
            idx = field['Reserved8']
            record[idx] = '{:d}'.format(msg[12])
            idx = field['HostTemperature']
            record[idx] = '{:0.3f}'.format(msg[13]/100.0)
            bch_mask = msg[14]
            tch_mask = msg[15]
            log_bch_mask = msg[16]
            log_tch_mask = msg[17]
            log_adc_mask = msg[18]
            log_adc_count = msg[19]
            num_idx = 20
            param = msg[num_idx:]
            for i in range(0, num_bch):
                if (bch_mask & (1<<i)):
                    value = param[BOOST_PARAM_LEN*i:]
                    bid = str(value[0] + 1) # bid = boost ID #
                    idx = field['VbstSet{}'.format(bid)]
                    record[idx] = '{:0.3f}'.format(value[1]/1000.0)
                    idx = field['VbstRead{}'.format(bid)]
                    record[idx] = '{:0.3f}'.format(value[2]/1000.0)
                    idx = field['Hcsa{}'.format(bid)]
                    record[idx] = '{:0.3f}'.format(value[3]/10.0)
                    idx = field['BoostPower{}'.format(bid)]
                    record[idx] = '{:0.3f}'.format(value[4]/1000.0)
            num_idx += num_bch * BOOST_PARAM_LEN
            param = msg[num_idx:]
            for i in range(0, num_tch):
                if (tch_mask & (1<<i)):
                    value = param[TILE_PARAM_LEN*i:]
                    tid = str(value[0] + 1) # tid = tile ID #
                    idx = field['Frequency{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[1]/1000.0)
                    idx = field['DutyCycle{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[2]/10.0)
                    idx = field['Vpzt{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[3]/100.0)
                    idx = field['Lcsa{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[4]/10.0)
                    idx = field['Power{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[5]/1000.0)
                    idx = field['Temperature{}'.format(tid)]
                    record[idx] = '{:0.3f}'.format(value[6]/100.0)
            num_idx += num_tch * TILE_PARAM_LEN
            param = msg[num_idx:]
            if log_adc_count > 0:
                idx = field['BchMask']
                record[idx] = '0x{:02x}'.format(log_bch_mask)
                idx = field['TchMask']
                record[idx] = '0x{:02x}'.format(log_tch_mask)
                idx = field['AdcMask']
                record[idx] = '0x{:02x}'.format(log_adc_mask)
                idx = field['AdcCount']
                record[idx] = '{:d}'.format(log_adc_count)
                for i in range(0, log_adc_count):
                    idx = field['AdcData{:03d}'.format(i+1)]
                    record[idx] = '{}'.format(param[i])
        # append CSV record
        block.append(record)

    with open(outfile, 'a', newline='') as f:
        writer = csv.writer(f)
        if parse_count == 0:
            writer.writerow(field)
        writer.writerows(block)

    return

def parse_message(dv: FroreComm, outfile: str, num_bch: int, num_tch: int,
    message: Optional[list[list[int]]]) -> None:
    """
    Parse one or more Event Trail messages in 3 different formats
    STM IDE memory dump format (space separated 32 bytes per row), JSON, CSV
    """
    if message == None:
        return

    global parse_count
    c = dv.const

    max_size = c['TRAIL_ADC_LOG_SIZE']
    fields = get_event_trail_fields(num_bch, num_tch, max_size)

    outfile_mem = '{}.txt'.format(outfile)
    outfile_json = '{}.json'.format(outfile)
    outfile_csv = '{}.csv'.format(outfile)

    #parse_message_mem(outfile_mem, message)
    #parse_message_json(dv, outfile_json, num_bch, num_tch, message)
    parse_message_csv(dv, outfile_csv, num_bch, num_tch, fields, message)

    parse_count += 1

def read_event_trail(dv: FroreComm, outfile: str, num_bch: int, num_tch: int,
    num_bytes: int, dev_lock: Lock) -> None:
    """
    Read Event Trail messages until buffer is empty and print results
    """
    global trail_buffer
    c = dv.const

    # check how many bytes to read
    with dev_lock:
        trail_left = dv.reg16_read(c['REG_EVENT_TRAIL_SIZE'])

    while trail_left > 0:
        dv.debug('Event Trail Left to Read: {} bytes'.format(trail_left))
        if trail_left < num_bytes:
            trail_read = trail_left
        else:
            trail_read = num_bytes
        # read Event Trail buffer and parse contained messages
        with dev_lock:
            buffer = dv.trail_read(trail_read)
        trail_buffer += buffer
        # extract messages
        mblock: list[list[int]] = []
        message, trail_buffer = get_message(trail_buffer) # get one meesage
        while message != None: # get remaining messages
            mblock.append(message)
            message, trail_buffer = get_message(trail_buffer)
        # parse messages
        parse_message(dv, outfile, num_bch, num_tch, mblock)
        trail_left -= trail_read
