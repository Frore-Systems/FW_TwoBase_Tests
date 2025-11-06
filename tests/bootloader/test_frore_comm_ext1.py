import pytest
from pyftdi.i2c import I2cNackError

from Frore_Comm import frore_utils
from tests.utils import *
from tests.bootloader.test_frore_comm import parse_FroreComm_response, ACK,NAK
import time, random

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                         [
                             [0x20002000, 512],  # Shared RAM area
                             [0x20000458, 16],
                             [0x20001FF0, 16],
                             [0x20000470, 32]
                         ])
def test_comm_op_enter_ram_write_valid_command(setup_function_scope, address: int, w_size: int):
    """
    Test entering RAM write mode on the Frore_Comm device using COMM_OP_ENTER_RAM_WRITE command.
    Drive board should respond with an ACK (0x01).
    After receiving this command, the device is ready to accept RAM write commands.  If commands other than
    RAM write commands receive, the device will not respond causing issue with sending subsequent commands.
    setup_function_scope is used to ensure each test gets a fresh device instance.
    NOTE: Even though valid addresses are used, only RAM write to memory address 0x20002000 will be used for
    subsequent Flash writes.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The write size to set for subsequent RAM write.  Maximum is 512 bytes.
    """
    fc, ps = setup_function_scope

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_RAM_WRITE'], 0, 10, 0])
               + w_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for ENTER RAM WRITE, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("size", ["long", "short"])
def test_comm_op_ram_write_with_mismatching_write_size(setup_function_scope, size: str):
    """
    Test RAM write on the Frore_Comm device with different write size from the COMM_OP_ENTER_RAM_WRITE
    command.  Drive board should respond with a NAK (0x02) for the invalid length RAM write attempt. Because
    I2C hangs after each test, setup_function_scope fixture is used so that each test should get a fresh
    instance of Frore_Comm and power supply.

    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param size: "long" to test with longer than valid length, "short" to test with shorter than valid length.
    """
    import random
    fc, ps = setup_function_scope
    address = 0x20002000
    valid_w_size = 32
    if size == "long":
        w_size = random.randint(valid_w_size + 1, valid_w_size + 20)
    else:
        w_size = random.randint(1 , valid_w_size - 1)
    data = [random.randint(0, 255) for _ in range(w_size)]

    # First send the ENTER RAM WRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_RAM_WRITE'], 0, 10, 0])
               + valid_w_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print("ENTER RAM WRITE command: " + str(list(command)))
    fc.port.write(command)
    response = fc.port.read(6)
    print("ENTER RAM WRITE response: " + str(list(response)))
    p_res = parse_FroreComm_response(response)
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['Status']))
    # Now send the RAM WRITE command with different write size
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_WRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)   # Reserved bytes
               + bytes(data)
               + bytes([fc.const['COMM_EOM']]))
    print("RAM WRITE command: " + str(list(command)))
    try:
        fc.port.write(command)
        response = fc.port.read(6)
        print("RAM WRITE response: " + str(list(response)))
    except I2cNackError as e:
        print(f"Got exception from RAM write: {e}: Test pass.")
        assert True
    except Exception as e:
        print(f"Unexpected exception: {e}")
        assert False
    else:
        assert False, "ERROR: Expected I2cNackError exception but command succeeded."

@pytest.mark.regression
@pytest.mark.parametrize("opcodename", ['COMM_OP_REG16_READ', 'COMM_OP_REG32_READ'])
def test_comm_op_read_with_invalid_eom(setup_function_scope, opcodename: str):
    """
    Test reading a register with an invalid EOM byte on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid read attempt.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    index = fc.const['REG_FIRMWARE_VERSION']
    command = bytes([fc.const['COMM_BOM'], fc.const[opcodename], 0, 10, 0,
                     index, 0, *[0]*9])  # Invalid EOM byte

    print(list(command))
    fc.port.write(command)
    response = fc.port.read(fc.const['COMM_RESP_SIZE_DEFAULT'] + 2)
    print(list(response))  # convert to integer array
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for missing EOM in {}, got 0x{:02x}.".format(opcodename, p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected response for missing EOM in {}, got 0x{:02x}.".format(opcodename, p_res['Status']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for missing EOM in {}, got 0x{:02x}.".format(opcodename, p_res['EOM']))

    expected_payload_length = 2 if opcodename == 'COMM_OP_REG16_READ' else 4
    assert p_res['PayloadLength'] == expected_payload_length, (
        "Error: Invalid Payload Length in response for missing EOM in {}, got {}."
        .format(opcodename, "p_res['PayloadLength']"))
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length does not match Payload Length for missing EOM in {}, got {} bytes for payload "
        "and {} for payload length.".format(opcodename, len(p_res['Payload']), p_res['PayloadLength']))
    assert p_res['Payload'] == [0]*expected_payload_length, (
        "Error: Data is not zeroed for missing EOM in {}, got {}."
        .format(opcodename, p_res['Payload']))

@pytest.mark.regression
@pytest.mark.parametrize("opcodename", ['COMM_OP_REG16_WRITE', 'COMM_OP_REG32_WRITE'])
def test_comm_op_write_with_missing_eom(setup_function_scope, opcodename: str):
    """
    Test writing to a register with a missing EOM byte on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid write attempt.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    regid = fc.const['REG_INIT_METRIC_1'].to_bytes(2, 'little')
    payload = [12, 34, 56, 78, 0, 0, 0, 0]

    # Construct a command with invalid payload length (payloadlen instead of 10)
    command = (bytes([fc.const['COMM_BOM'], fc.const[opcodename], 0, 10, 0]) + regid
               + bytes([*payload, 0])) # Missing EOM byte
    print(list(command))
    fc.port.write(command)
    expected_length = 6
    response = fc.port.read(expected_length)
    print(list(response))  # convert to integer array
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected response for missing EOM write, got 0x{:02x}.".format(p_res['Status']))

def test_comm_op_read_with_invalid_payload_length(setup_function_scope):
    """
    Test reading a register with an invalid payload length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length read attempt.  Correct payload length is 10 bytes for
    COMM_OP_REG16_READ & COMM_OP_REG32_READ messages, but here we send 14 bytes.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    index = fc.const['REG_FIRMWARE_VERSION']

    # Construct a command with invalid payload length (20 instead of 16)
    command = bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_REG16_READ'], 0, 14, 0,
                     index, 0, *[0]*8, fc.const['COMM_EOM']])
    fc.port.write(command)
    response = fc.port.read(fc.const['COMM_RESP_SIZE_DEFAULT'] + 2)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for missing EOM in RAM read, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
@pytest.mark.parametrize("opcodename", ['COMM_OP_REG16_WRITE', 'COMM_OP_REG32_WRITE'])
@pytest.mark.parametrize("payloadlen", [8, 12])
def test_comm_op_write_with_invalid_payload_length(setup_function_scope, opcodename: str, payloadlen: int):
    """
    Test writing to a register with an invalid payload length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length write attempt.  Correct payload length is 10 bytes for
    COMM_OP_REG16_WRITE & COMM_OP_REG32_WRITE messages, but here we send 8 & 12 bytes.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    regid = fc.const['REG_INIT_METRIC_1'].to_bytes(2, 'little')
    plen = payloadlen.to_bytes(2, 'little')
    payload = [12, 34, 56, 78, 0, 0, 0, 0]

    # Construct a command with invalid payload length (payloadlen instead of 10)
    command = (bytes([fc.const['COMM_BOM'], fc.const[opcodename], 0]) + plen + regid
               + bytes([*payload, fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    expected_length = 6
    response = fc.port.read(expected_length)
    print(list(response))  # convert to integer array
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for RAM read, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
@pytest.mark.parametrize("address", [0x1fffffff, 0x20009000])
def test_comm_op_enter_ram_write_invalid_address(setup_function_scope, address: int):
    """
    Test entering RAM write mode on the Frore_Comm device using COMM_OP_ENTER_RAM_WRITE command
    with invalid address.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    """
    fc, ps = setup_function_scope
    w_size = 1

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_RAM_WRITE'], 0, 10, 0])
               + w_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for ENTER RAM WRITE with invalid address, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for ENTER RAM WRITE, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['EOM']))


@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                         [
                             [0x20002000, 8193],  # Above max RAM write size of 8192 bytes
                             [0x20002000, 0xFFFF]      # Excessively large size
                         ])
def test_comm_op_enter_ram_write_invalid_write_size(setup_function_scope, address: int, w_size: int):
    """
    Test entering RAM write mode on the Frore_Comm device using COMM_OP_ENTER_RAM_WRITE command
    with invalid write size (exceed RAM region).  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The RAM address to write the data to.
    """
    fc, ps = setup_function_scope

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_RAM_WRITE'], 0, 10, 0])
               + w_size.to_bytes(2, "little", signed=False)
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for ENTER RAM WRITE with invalid address, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for ENTER RAM WRITE, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                            [
                                [0x08002000, 256],  # Below valid Flash write range
                                [0x08004000, 256],  # Above valid Flash write range
                                [0x08003000, 258],  # Write exceeding OTD boundary
                                [0x080030F0, 256],  # Write exceeding OTD boundary
                                [0x08003100, 256],  # Write into LTD segment
                                [0x08003700, 258],  # Write into LTD segment and exceed its boundary
                                [0x08003F00, 258],  # Write exceeding CFG boundary
                                [0x08003702, 256]  #  Write into LTD segment with unaligned address
                            ]
                         )
def test_comm_op_flash_dwrite_with_invalid_address(setup_function_scope, address, w_size):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_DWRITE command with invalid
    address.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The number of bytes to write.
    """
    fc, ps = setup_function_scope
    data = [random.randint(0, 255) for _ in range(w_size)]
    ram_address = 0x20002000  # Use a RAM address for temporary data storage

    # First write the data to RAM
    write_2_ram(fc, ram_address, data)

    # Construct the COMM_OP_FLASH_DWRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_DWRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(frore_utils.fletcher32(data, w_size), 4, 'little')   # Checksum
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for Flash write with invalid address, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for Flash write, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for Flash write, got 0x{:02x}.".format(p_res['EOM']))


@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                            [
                                [0x08003000, 254],  # Below min write size
                                [0x08003000, 2050]  # Above max write size
                            ]
                        )
def test_comm_op_flash_dwrite_with_invalid_size(setup_function_scope, address, w_size):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_DWRITE command with invalid
    write size.  Drive board should respond with a NAK (0x02).
    NOTE: The write size must be even
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The number of bytes to write.
    """
    fc, ps = setup_function_scope
    data = [random.randint(0, 255) for _ in range(w_size)]
    ram_address = 0x20002000  # Use a RAM address for temporary data storage

    # First write the data to RAM
    write_2_ram(fc, ram_address, data)

    # Construct the COMM_OP_FLASH_DWRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_DWRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(frore_utils.fletcher32(data, w_size), 4, 'little')   # Checksum
               + bytes([fc.const['COMM_EOM']]))
    #print(list(command))
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    #print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for Flash write with invalid size, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
def test_comm_op_flash_dwrite_with_invalid_checksum(setup_function_scope):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_DWRITE command with invalid
    checksum.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    address = 0x08003000
    w_size = 512
    data = [random.randint(0, 255) for _ in range(w_size)]
    ram_address = 0x20002000  # Use a RAM address for temporary data storage

    # First write the data to RAM
    write_2_ram(fc, ram_address, data)

    # Construct the COMM_OP_FLASH_DWRITE command with invalid checksum
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_DWRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(0xDEADBEEF, 4, 'little')   # Invalid Checksum
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for Flash write with invalid checksum, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                            [
                                [0x08000000, 16],   # Start of Flash memory
                                [0x07FFFFF0, 16],   # Below valid Flash range
                                [0x08002FFF, 1],    # Below OTD region
                                [0x08020000, 1]     # Above valid Flash read/write area
                            ]
                        )
def test_comm_op_flash_dread_with_invalid_address(setup_function_scope, address, size):
    """
    Test reading from Flash on the Frore_Comm device using COMM_OP_FLASH_DREAD command with invalid
    address.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_DREAD'], 0, 10, 0])
               + size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))

    fc.port.write(command)
    response = fc.port.read(size+6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for ENTER RAM WRITE with invalid address, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == size, (
        "Error: Invalid Payload Length in response for ENTER RAM WRITE, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                            [
                                 [0x08003000, 513],
                                 [0x08003FFF, 2]
                            ]
                         )
def test_comm_op_flash_dread_with_invalid_size(setup_function_scope, address, size):
    """
    Test reading from Flash on the Frore_Comm device using COMM_OP_FLASH_DREAD command with invalid
    read size.  Max size of the read is 512 bytes.  Drive board should respond with a NAK (0x02) when size > 512 bytes
    or when read size exceeds the flash memory boundary [0x08003000, 0x08003FFF].
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_DREAD'], 0, 10, 0])
               + size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))

    fc.port.write(command)
    response = fc.port.read(size+6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for ENTER RAM WRITE with invalid address, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == size, (
        "Error: Invalid Payload Length in response for ENTER RAM WRITE, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                             [
                                 [0x1FFFF000, 16], # Below valid RAM range
                                 [0x21000000, 16]  # Above valid RAM range
                             ]
                         )
def test_comm_op_ram_write_invalid_address(setup_function_scope, address: int, size: int):
    """
    Test writing to RAM on the Frore_Comm device using COMM_OP_RAM_WRITE command with invalid
    address.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The RAM address to write the data to.
    :param size: The write size in bytes
    """
    fc, ps = setup_function_scope
    data = [random.randint(0, 255) for _ in range(size)]
    # Construct the command
    response = fc.ram_write(address, data, False)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected Status in response for RAM write, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for RAM write, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM write, got 0x{:02x}.".format(p_res['EOM']))


@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                         [
                             [0x08003000, 256],     # Above the Flash APP region
                             [0x08020000, 256],     # Below the Flash APP region
                             [0x0801FF00, 258]      # Write beyond the Flash APP region
                         ])
def test_comm_op_flash_pwrite_invalid_address(setup_function_scope, address, w_size):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_PWRITE command with invalid
    address.  Drive board should respond with a NAK (0x02).  Valid flash address range for this command
    is [0x08004000, 0x0801FFFF].
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The flash address to write the data to.
    :param w_size: The number of bytes to write.
    """
    fc, ps = setup_function_scope

    ram_address = 0x20002000  # Use a RAM address for temporary data storage
    data = [random.randint(0, 255) for _ in range(w_size)]
    # First write the data to RAM
    write_2_ram(fc, ram_address, data)
    # Construct COMM_OP_FLASH_PWRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_PWRITE'], 0])
               + int.to_bytes(10, 2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(frore_utils.fletcher32(data, w_size), 4, 'little')
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    time.sleep(0.5)     # Give FW enough time to write to flash
    response = fc.port.read(6)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected status in response for COMM_OP_FLASH_PWRITE command, got 0x{:02x}."
        .format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for COMM_OP_FLASH_PWRITE command, got {}."
        .format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for COMM_OP_FLASH_PWRITE command, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                         [
                             [0x08004000, 254],     # Below min write size
                             [0x08004000, 2050],    # Above max write size
                         ])
def test_comm_op_flash_pwrite_invalid_write_size(setup_function_scope, address, w_size):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_PWRITE command with invalid
    write size.  Drive board should respond with a NAK (0x02).  The min write size is 256 bytes and
    the max write size is 2048 bytes and must be even (fletcher32's requirement).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The number of bytes to write.
    """
    fc, ps = setup_function_scope
    data = [random.randint(0, 255) for _ in range(w_size)]
    ram_address = 0x20002000  # Use a RAM address for temporary data storage

    # First write the data to RAM
    write_2_ram(fc, ram_address, data)

    # Construct the COMM_OP_FLASH_DWRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_PWRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")  # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(frore_utils.fletcher32(data, w_size), 4, 'little')  # Checksum
               + bytes([fc.const['COMM_EOM']]))
    # print(list(command))
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    # print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected status in response for Flash write with invalid size, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
def test_comm_op_flash_pwrite_with_invalid_checksum(setup_function_scope):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_PWRITE command with invalid
    checksum.  Drive board should respond with a NAK (0x02).
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    address = 0x08003000
    w_size = 512
    data = [random.randint(0, 255) for _ in range(w_size)]
    ram_address = 0x20002000  # Use a RAM address for temporary data storage

    # First write the data to RAM
    write_2_ram(fc, ram_address, data)

    # Construct the COMM_OP_FLASH_DWRITE command with invalid checksum
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_PWRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(0xDEADBEEF, 4, 'little')   # Invalid Checksum
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for Flash write with invalid checksum, got 0x{:02x}.".format(p_res['Status']))

@pytest.mark.regression
@pytest.mark.parametrize("opcodename", ['COMM_OP_REG16_WRITE', 'COMM_OP_REG32_WRITE'])
@pytest.mark.parametrize("size", ["long", "short"])
def test_comm_op_write_with_invalid_message_length(setup_function_scope, opcodename: str, size: str):
    """
    Test writing to a register with an invalid length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length write attempt.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    import random
    fc, ps = setup_function_scope
    #print(fc.get_info())
    regid = fc.const['REG_INIT_METRIC_1'].to_bytes(2, 'little')
    payload = [12, 34, 56, 78] + [0]*16  # 8 bytes of write data

    # The COMM OP WRITE's message is 16 byte long where the payload length is 10 bytes.
    # Here we test with both shorter and longer lengths by adjusting the payload size.
    # The first two bytes of the payload is the register index (2 bytes) followed by
    # 8 bytes of write data (for REG16 write).  So the payload length should be 10 bytes.
    # We will randomly choose a length shorter than 10 bytes (0 to 7)
    # or longer than 10 bytes (9 to 20).
    if size == "long":
        plength = random.randint(9, 20)
    else:
        plength = random.randint(0 , 7)

    command = (bytes([fc.const['COMM_BOM'], fc.const[opcodename], 0, 10, 0]) + regid
               + bytes([*payload[:plength], fc.const['COMM_EOM']]))
    print(str(list(command)) + f" Length: {len(command)}")
    try:
        fc.port.write(command)
    except I2cNackError as e:
        #print(f"Unexpected exception: {e}")
        assert True
    except Exception as e:
        print(f"Unexpected exception: {e}")
        assert False
    finally:
        fc.port.flush()

@pytest.mark.regression
def test_comm_op_ram_write_with_before_comm_op_enter_ram_write(setup_function_scope):
    """
    Test writing to RAM on the Frore_Comm device using COMM_OP_RAM_WRITE command
    without first sending COMM_OP_ENTER_RAM_WRITE command.  Drive board should
    respond with a NAK (0x02) for the invalid write attempt.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    address = 0x20002000
    data = [random.randint(0, 255) for _ in range(32)]
    w_size = len(data)

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_WRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4)   # Reserved bytes
               + bytes(data)
               + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    try:
        fc.port.write(command)
        response = fc.port.read(6)
        print(list(response))
    except I2cNackError as e:
        print(e)
        assert True
    except Exception as e:
        print(f"Unexpected exception: {e}")
        assert False
    else:
        assert False, "ERROR: Expected I2cNackError exception but command succeeded."
    finally:
        fc.port.flush()

@pytest.mark.regression
@pytest.mark.parametrize("size", ["long", "short"])
def test_comm_op_read_with_invalid_message_length(setup_function_scope, size: str):
    """
    Test reading a register with an invalid length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length read attempt.
    :param setup_function_scope: The setup_function_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    index = fc.const['REG_FIRMWARE_VERSION']

    # The COMM OP READ's message is 16 byte long where the payload length is 10 bytes.
    # Here we test with both shorter and longer lengths by adjusting the payload size.
    # The first two bytes of the payload is the register index (2 bytes) followed by
    # 8 bytes of read data (for REG16 read).  So the payload length should be 10 bytes.
    # We will randomly choose a length shorter than 10 bytes (0 to 7)
    # or longer than 10 bytes (9 to 20).
    if size == "long":
        plength = random.randint(9, 20)
    else:
        plength = random.randint(0 , 7)
    command = bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_REG16_READ'], 0, 10, 0,
                     index, 0, *[0]*plength, fc.const['COMM_EOM']])
    print(str(list(command)) + f" Length: {len(command)}")
    # Send the command directly to the port to avoid any pre-processing by the Frore_Comm class.
    # The Frore_Comm class expects a valid message and will raise an exception if the
    # message is invalid.
    # We want to test the device's response to a message with invalid message length.
    # So we bypass the Frore_Comm class and send the raw command to the device.
    # The device should respond with a NAK (0x02) for the invalid length read attempt.
    # Note that the Frore_Comm class adds 2 bytes to the response for the BOM and EOM bytes.
    # So we read COMM_RESP_SIZE_DEFAULT + 2 bytes from the port.
    # The response should be [BOM, NAK, ..., EOM]
    # where NAK is 0x02.
    # Test passes ff the device respond with a NAK.  Test fails otherwise.

    # NOTE: It is observed that FW does not respond to the invalid length message and the
    # pyftdi library raises an I2cNackError exception.  So we catch the exception and
    # assert that it is indeed an I2cNackError.  If any other exception is raised, the
    # test fails.  If no exception is raised, the test also fails.
    try:
        fc.port.write(command)
    except I2cNackError:
        assert True
    except Exception as e:
        print(f"Unexpected exception: {e}")
        assert False

