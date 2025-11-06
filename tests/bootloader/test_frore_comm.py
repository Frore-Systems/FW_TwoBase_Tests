import random
import time

import pytest
from pyftdi.i2c import I2cNackError

from Frore_Comm.frore_comm import reflash_section
from tests.conftest import reg16_read, reg32_read, reg16_write, reg32_write, SystemStatus
import Frore_Comm.frore_utils as frore_utils
from tests.utils import *

@pytest.mark.regression
@pytest.mark.parametrize("opcodename", ['COMM_OP_REG16_READ', 'COMM_OP_REG32_READ'])
@pytest.mark.parametrize("register", ['REG_FIRMWARE_VERSION', 'REG_HARDWARE_VERSION',
                                        'REG_FIRMWARE_BUILD_NUMBER', 'REG_FLASH_COPY_ADDR',
                                        'REG_PRODUCT_NAME_ADDR', 'REG_REGISTER_ADDR',
                                        'REG_SERIAL_NUMBER'] )

def test_comm_op_read_with_valid_register(setup_module_scope, opcodename: str, register: str):
    """
    Test reading a valid register on the Frore_Comm device.  Drive board should
    respond with a ACK (0x01) for the invalid read attempt.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    registerid = fc.const[register]
    command = bytes([fc.const['COMM_BOM'], fc.const[opcodename], 0, 10, 0,
                     registerid, 0, *[0]*9])  # Invalid EOM byte

    fc.port.write(command)
    if opcodename == 'COMM_OP_REG16_READ':
        expected_msg_length = 8
        payload_length = 2
    else:
        expected_msg_length = 10
        payload_length = 4

    response = fc.port.read(expected_msg_length)
    #print(list(response))  # convert to integer array

    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Unexpected BOM byte.  Got 0x{:02x}".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        f"Error: Unexpected status for valid {opcodename} with {register}. Got {p_res['Status']}.")
    assert p_res['PayloadLength'] == payload_length, (
        f"Error: Expected payload length {payload_length}. Got {p_res['PayloadLength']} "
    )
    assert len(p_res['Payload']) == payload_length, (
        f"Error: Payload is not equal to the payload length. Got {len(p_res['Payload'])} "
    )
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Unexpected EOM byte.  Got 0x{:02x}".format(p_res['EOM']))


@pytest.mark.regression
@pytest.mark.parametrize("operation", [reg16_read, reg32_read], indirect=True)
@pytest.mark.parametrize("registerid", [0xffff, 1000, 12])
def test_comm_op_read_invalid_registers(setup_module_scope, operation, registerid):
    """
    Test reading an invalid register from the Frore_Comm device.  Drive board should
    respond with an ACK without data (0) for the invalid register read attempt.
    As of 2.6.0.0, even though the register is invalid (for example, register 12) and in
    the valid range of registers, the device responds with ACK and some data.  This is
    considered acceptable behavior.  Only test with boundary of the registers range
    :param registerid: Register id to be tested.
    """
    fc, ps = setup_module_scope
    response = operation(fc, registerid, False)
    p_res = parse_FroreComm_response(response)
    assert p_res['Status'] == ACK, \
        f"Expected ACK (0x01) for invalid register read, got {response[1]} for register ID {registerid}."

@pytest.mark.parametrize("operation", [reg16_write, reg32_write], indirect=True)
def test_comm_op_write_invalid_registers(setup_module_scope, operation):
    """
    Test writing to an invalid register on the Frore_Comm device.  Drive board should
    respond with a NAK (0xFF) for the invalid register write attempt.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    response = operation(fc, 0xffff, 1234, False)
    assert response[1] == 0x02, "Error: Expected NAK (0x02) for invalid register write, got {response[1]}."

@pytest.mark.regression
@pytest.mark.parametrize("operation", [reg16_write, reg32_write])
@pytest.mark.parametrize("registername", ['REG_FIRMWARE_VERSION', 'REG_HARDWARE_VERSION',
                                        'REG_FIRMWARE_BUILD_NUMBER', 'REG_FLASH_COPY_ADDR',
                                        'REG_PRODUCT_NAME_ADDR', 'REG_REGISTER_ADDR',
                                        'REG_SERIAL_NUMBER'] )
def test_comm_op_write_readonly_registers(setup_module_scope, operation, registername):
    """
    Test writing to a read-only register on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the read-only register write attempt.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    reg = fc.const[registername]
    response = operation(fc, reg, 1234, False)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected status in response for writing to read-only "
        "register ({}), got 0x{:02x}.".format(reg, p_res['Status']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for missing EOM in {}, got 0x{:02x}.".format(operation, p_res['EOM']))

    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for missing EOM in {}, got {}."
        .format(operation, "p_res['PayloadLength']"))
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length does not match Payload Length for missing EOM in {}, got {} bytes for payload "
        "and {} for payload length.".format(operation, len(p_res['Payload']), p_res['PayloadLength']))


@pytest.mark.skip(reason="This test causes i2c bus hang. Needs to power cycle the device to recover.")
def test_comm_op_with_invalid_bom(setup_module_scope):
    """
    Test sending a command with an invalid BOM byte on the Frore_Comm device.  Drive board should not
    respond to the command.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    pass


@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                         [[0x20001FF0, 16],  # 536879088. Boot parameters area
                          [0x20000458, 20],  # 536872024.  RAM address of Product Name string ("Bayhill")
                          [0x20002000, 512],   # 536870912.  Shared RAM area
                          [0x20000470, 256]])     # 536872048. RAM address of registers and size to read
def test_comm_op_ram_read_valid_command(setup_module_scope, address: int, size: int):
    """
    Test reading from RAM on the Frore_Comm device using COMM_OP_RAM_READ command.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    r_size = random.randint(4, size)

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_READ'], 0, 10, 0])
               + r_size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4) + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(r_size+6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for RAM read, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == r_size, (
        "Error: Invalid Payload Length in response for RAM read, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM read, got 0x{:02x}.".format(p_res['EOM']))
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length does not match Payload Length for RAM read, got {} bytes for payload "
        "and {} for payload length.".format(len(p_res['Payload']), p_res['PayloadLength']))


@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                         [[0x20001FF0, 17],  # Boot parameters area
                          [0x20000458, 21],  # RAM address of Product Name string ("Bayhill").
                          [0x20002000, 513],   # Shared RAM area.  Cap is 512 bytes per FW Reference Manual size (???).
                          [0x20000470, 257]])     # RAM address of registers and size to read
def test_comm_op_ram_read_invalid_read_size(setup_module_scope, address: int, size: int):
    """
    Test reading from RAM on the Frore_Comm device using COMM_OP_RAM_READ command with invalid
    message length.  Drive board should respond with a NAK (0x02).
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope

    # Construct the command with invalid length (14 instead of 16)
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_READ'], 0, 10, 0])
               + size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0]*4) + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(size+6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected Status in response for RAM read, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == size, (
        "Error: Payload length in response does not match requested size for RAM read, got {} bytes "
        "for requested size {}.".format(len(response), size))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM read, got 0x{:02x}.".format(p_res['EOM'])
    )
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length in response does not match Payload Length for RAM read, got {} bytes for payload "
        "and {} for payload length.".format(len(p_res['Payload']), p_res['PayloadLength'])
    )
    assert list(p_res['Payload']) == [0]*size, (
        "Error: Data is not zeroed for invalid RAM read, got {}."
        .format(p_res['Payload'])
    )

@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                         [
                             [0x20001FEF, 16],  # Boot parameters area
                             [0x20000457, 16],  # RAM address of Product Name string ("Bayhill")
                             [0x20001FFF, 16],   # Shared RAM area
                             [0x2000046F, 16],    # RAM address of registers and size to read
                             [0x1FFFF000, 16],    # Below valid RAM range
                             [0x21000000, 16]     # Above valid RAM range
                          ]
                         )
def test_comm_op_ram_read_invalid_address(setup_module_scope, address: int, size):
    """
    Test reading from RAM on the Frore_Comm device using COMM_OP_RAM_READ command.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope

    # Construct the command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_READ'], 0, 10, 0])
               + size.to_bytes(2, "little")
               + address.to_bytes(4, "little")
               + bytes([0] * 4) + bytes([fc.const['COMM_EOM']]))
    print(list(command))
    fc.port.write(command)
    response = fc.port.read(size + 6)
    print(list(response))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for RAM read, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == size, (
        "Error: Payload length does not match requested size for RAM read, got {} bytes "
        "for requested size {}.".format(len(response), size))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM read, got 0x{:02x}.".format(p_res['EOM'])
    )
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length does not match Payload Length for RAM read, got {} bytes for payload "
        "and {} for payload length.".format(len(p_res['Payload']), p_res['PayloadLength'])
    )
    assert list(p_res['Payload']) == [0]*size, (
        "Error: Data is not zeroed for invalid RAM read, got {}."
        .format(p_res['Payload'])
    )


@pytest.mark.regression
@pytest.mark.parametrize("address, data",
                            [
                                [0x20002000, [random.randint(0, 255) for _ in range(32)]],
                                [0x20002020, [random.randint(0, 255) for _ in range(16)]],
                                [0x20002100, [random.randint(0, 255) for _ in range(512-10)]],
                                [0x20002FF0, [random.randint(0, 255) for _ in range(16)]],
                            ]
                         )
def test_comm_op_ram_write_valid_command(setup_module_scope, address: int, data: list[int]):
    """
    Test writing to RAM on the Frore_Comm device using COMM_OP_RAM_WRITE command.  After the RAM write
    command is sent, FW automatically exits RAM write mode. We will read back and compare to the RAM
    write ensure they match. The test assumes that the RAM addresses used are valid and writable.
    The test writes random data to the specified RAM addresses.

    NOTE:
    1. In order to writo RAM, the device must first be put into RAM write mode by sending the
    COMM_OP_ENTER_RAM_WRITE command.
    2. The write size of the COMM_OP_RAM_WRITE command must be exactly the same as that entered
    in the COMM_OP_ENTER_RAM_WRITE command.  FW expects this and will NAK the write command if sizes
    do not match.
    3. Upon receiving the COMM_OP_ENTER_RAM_WRITE command, FW will wait for a single RAM write command
    immediately following. If any other command is received before the RAM write command, FW will not
    respond causing I2C bus hang.
    4. After the RAM write command is processed, FW automatically exits RAM write mode.

    Therefore, to test multiple RAM writes, we directly use the Frore_Comm class's ram_write() method
    for this test since it handles the ENTER RAM WRITE command internally before sending the RAM WRITE
    command.

    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param data: The data to write as a list of integers.
    """
    fc, ps = setup_module_scope
    # Construct the command
    print("data = " + str(list(data)))
    response = fc.ram_write(address, data, False)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for RAM write, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for RAM write, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM write, got 0x{:02x}.".format(p_res['EOM']))

    response = fc.ram_read(address, len(data), False)
    p_res = parse_FroreComm_response(response)
    print(list(p_res['Payload']))
    assert p_res["Payload"] == data, (
        "Error: Data read from RAM does not match data written, got {}.".format(list(p_res['Payload'])))

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                            [
                                [0x20002000, 8 * 512],  # 4 ram writes with multiple of 512 bytes each
                                [0x20002000, 1200]        # Write size not multiple of 512 bytes
                            ]
                        )
def test_multiple_ram_writes_valid_command(setup_module_scope, address: int, w_size: int):
    """
    Test writing to RAM multiple times to the Frore_Comm device using the ram_write() method
    of the Frore_Comm class.  After the RAM write commands are sent, FW automatically exits RAM write mode.
    We will read back and compare to the RAM write ensure they match.  Each ram_write() call writes
    up to 512 bytes at a time.  So multiple ram_write calls are made to write the total data size.

    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The total number of bytes to write in multiple writes.
    """
    fc, ps = setup_module_scope
    data = [random.randint(0, 255) for _ in range(w_size)]
    #print("data = " + str(list(data)))
    r_size = 512
    for i in range(0, w_size, r_size):
        chunk_size = min(r_size, w_size - i)
        chunk_data = data[i:i+chunk_size]
        #print(f"Writing chunk at address 0x{address + i:08X} of size {chunk_size}")
        response = fc.ram_write(address + i, chunk_data, False)
        p_res = parse_FroreComm_response(response)
        assert p_res['Status'] == ACK, (
            "Error: Unexpected status in response for RAM write chunk, got 0x{:02x}.".format(p_res['Status']))

        response = fc.ram_read(address + i, chunk_size, False)
        p_res = parse_FroreComm_response(response)
        print(list(p_res['Payload']))
        assert p_res["Payload"] == chunk_data, (
            "Error: Data read from RAM does not match data written, got {}.".format(list(p_res['Payload'])))

@pytest.mark.regression
def test_comm_op_ram_write_with_address_different_from_enter_ram_write(setup_module_scope):
    """
    Test writing to RAM on the Frore_Comm device using COMM_OP_RAM_WRITE command
    with address different from that used in the preceding COMM_OP_ENTER_RAM_WRITE command.
    Drive board should respond with a NAK (0x02) for the invalid write attempt.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    enter_address = 0x20002000
    write_address = 0x20002010
    w_size = 16
    data = [random.randint(0, 255) for _ in range(w_size)]


    # First send the ENTER RAM WRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_RAM_WRITE'], 0, 10, 0])
               + w_size.to_bytes(2, "little")
               + enter_address.to_bytes(4, "little")
               + bytes([0]*4)
               + bytes([fc.const['COMM_EOM']]))
    print("ENTER RAM WRITE command: " + str(list(command)))
    fc.port.write(command)
    response = fc.port.read(6)
    print("ENTER RAM WRITE response: " + str(list(response)))
    p_res = parse_FroreComm_response(response)
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for ENTER RAM WRITE, got 0x{:02x}.".format(p_res['Status']))

    # Now send the RAM WRITE command with different address
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_RAM_WRITE'], 0])
               + (10 + w_size).to_bytes(2, "little")
               + w_size.to_bytes(2, "little")
               + write_address.to_bytes(4, "little")
               + bytes([0]*4)   # Reserved bytes
               + bytes(data)
               + bytes([fc.const['COMM_EOM']]))
    print("RAM WRITE command: " + str(list(command)))
    fc.port.write(command)
    response = fc.port.read(6)
    print("RAM WRITE response: " + str(list(response)))
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, \
        "Error: Invalid Status in response for RAM write with different address, got 0x{:02x}.".format(p_res['Status'])
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for RAM write, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for RAM write, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
@pytest.mark.parametrize("address, size",
                            [
                                [0x08003000, 1],  # Start Flash area
                                [0x08003200, 512],  # Max read size per command
                                [0x08003800, 16], # Start of Static Config region
                                [0x08003FFF, 1]  # End of Static Config region
                            ]
                         )
def test_comm_op_flash_dread_with_valid_command(setup_module_scope, address, size):
    """
    Test reading from Flash on the Frore_Comm device using COMM_OP_FLASH_DREAD command.  Readable flash segment
    is [0x08003000, 0x08003FFF], which contains the OTD and LTD (data) segments. The COMM_OP_FLASH_DREAD command can
    read up to 512 bytes at a time.

    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The flash address to read from.
    :param size: The number of bytes to read.
    """
    fc, ps = setup_module_scope

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
        "Error: Invalid BOM in response for Flash read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        "Error: Invalid Status in response for Flash read, got 0x{:02x}.".format(p_res['Status']))
    assert p_res['PayloadLength'] == size, (
        "Error: Invalid Payload Length in response for Flash read, got {}.".format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for Flash read, got 0x{:02x}.".format(p_res['EOM']))
    assert len(p_res['Payload']) == p_res['PayloadLength'], (
        "Error: Data length does not match Payload Length for Flash read, got {} bytes for payload "
        "and {} for payload length.".format(len(p_res['Payload']), p_res['PayloadLength']))

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size",
                         [
                             [0x08003000, 256], # Min write size
                             [0x08003800, 2048]  # Max write size
                          ]
                         )
def test_comm_op_flash_dwrite_with_valid_command(setup_module_scope, address: int, w_size: int):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_DWRITE command.  This command
    is used to write data to the Flash memory region [0x08003000, 0x08003FFF], which contains
    the OTD and LTD (data) segments.  The write size must be between 256 and 2048 bytes.  The test writes
    random data to the specified Flash address.
    NOTE:
    1. This test assumes that the Flash memory region [0x08003000, 0x08003FFF] is
    writable and that writing random data to this region will not affect device operation.  Also,
    it requires test data to be written in RAM first (via COMM_OP_ENTER_RAM_WRITE and COMM_OP_RAM_WRITE
    commands) before performing writing to Flash.
    2. After writing to Flash, the test reads back the data to verify that the write was successful.
    3. We'll be utilizing the Frore_Comm class's ram_write() method to write data to RAM first,
    then use the COMM_OP_FLASH_DWRITE command to write from RAM to Flash.

    CAUTION: Flash memory typically has wear limits. Repeatedly running this test may
    reduce the lifespan of the Flash memory. Use with caution.  Also because the first 12 bytes of the OTD
    segment contains the APP info and the last 4 bytes contains the drive's serial number, writing random data
    should not overwrite these value.  Therefore, we avoid writing to these bytes of the OTD segment.  The
    test writes to the middle portion of the OTD segment and the entire LTD segment. Exercise caution when
    running this test as it will overwrite parts of the OTD and LTD segments.  Advise to back up these segments
    before running this test.  We'll back up the entire Flash region before running this test and restore it after
    the test.

    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    :param address: The address to send the data to.
    :param w_size: The number of bytes to write.
    """
    fc, ps = setup_module_scope

    # Back up the original Flash content at the specified address
    backup_flash = read_ram_flash(fc.flash_dread, address, w_size)
    # for i in range(0, w_size, fc.const['FLASH_WRITE_MIN_SIZE']): # Read back in 256-byte chunks for backup
    #     backup_flash += fc.flash_dread(address + i, fc.const['FLASH_WRITE_MIN_SIZE'])

    # Generate random data to write
    data = [random.randint(0, 0xFF) for _ in range(w_size)]

    try:
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
        # print(list(command))
        # Write the command to Flash write
        fc.port.write(command)
        time.sleep(1)  # Wait for Flash write to complete
        # Read the response
        response = fc.port.read(6)
        # print(list(response))
        p_res = parse_FroreComm_response(response)
        assert p_res['BOM'] == fc.const['COMM_BOM'], (
            "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
        assert p_res['Status'] == ACK, (
            "Error: Invalid Status in response for Flash write, got 0x{:02x}.".format(p_res['Status']))
        assert p_res['PayloadLength'] == 0, (
            "Error: Invalid Payload Length in response for Flash write, got {}.".format(p_res['PayloadLength']))
        # Verify the data was written correctly by reading back
        read_back = read_ram_flash(fc.flash_dread, address, w_size)
        assert read_back == data, (
            "Error: Data read back from Flash does not match data written, got {}.".format(list(read_back)))
    except (AssertionError, I2cNackError, Exception) as e:
        print(f"Flash write failed: {e}")
        assert False, e
    finally:
        # Restore otd segment if write failed
        reflash_section(fc, address, backup_flash, 'DATA')

@pytest.mark.regression
@pytest.mark.parametrize("address, w_size, data_offset",
                         [
                             [0x08004800, 2048, 0x800],   # Max write size
                             [0x08004000, 256, 0],      # Min write size
                             [0x08004100, 256, 256]     # Write to random address
                         ])
def test_comm_op_flash_pwrite_valid_command(setup_module_scope, setup_pwrite_data,
                                            address:int, w_size: int, data_offset: int):
    """
    Test writing to Flash on the Frore_Comm device using COMM_OP_FLASH_PWRITE command.  This command
    is used for writing piezo drive app to the Flash memory region [0x08004000, 0x0801FFFF], which is
    reserved for the APP.  The write size per command must be between 256 and 2048 bytes and an even
    number.  Because of the RAM size and write size of write commands limitation, multiple ram write
    and pwrite commands may be needed to write the entire app.  Also, the payload of the flash_pwrite
    command shall always be encrypted.
    In this test, we will only test the min (256 bytes) and max (2048 bytes) write size of the
    flash_pwrite command and write to continuous flash addresses using partial pkg file to avoid
    corrupting the app (hopefully).

    NOTE:
    1. This test assumes that the Flash memory region [0x08004000, 0x0801FFFF] is writable.
    2. Because we can't directly read back the APP segment to verify the write commands, this test will
    only check for ACK response from the device after the write command.
    3. We'll be utilizing the Frore_Comm class's ram_write() method to write data to RAM first,
    then use the COMM_OP_FLASH_PWRITE command to write from RAM to Flash.

    CAUTION: Flash memory typically has wear limits. Repeatedly running this test may reduce the lifespan
    of the Flash memory. Also writing random data to this region will likely corrupt
    the piezo drive app and render the device non-functional.  Therefore, this test should be run with
    caution and only on test devices that can be re-flashed with a valid app if needed.
    It is recommended to use valid fw file (.pkg) when running this test

    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    :param setup_pwrite_data: The setup_pwrite_data fixture providing data for pwrite commands
    :param address: The flash address to write the data to.
    :param w_size: The number of bytes to write.
    :param data_offset: The offset of the test data to write to the flash memory.
    """
    fc, ps = setup_module_scope
    fdata = setup_pwrite_data

    ram_address = 0x20002000  # Use a RAM address for temporary data storage
    data = list(fdata[data_offset:data_offset+w_size])
    # First write the data to RAM
    write_2_ram(fc, ram_address, data)
    # Write to flash via FroreComm's flash_pwrite function
    # Construct the COMM_OP_FLASH_PWRITE command
    command = (bytes([fc.const['COMM_BOM'], fc.const['COMM_OP_FLASH_PWRITE'], 0])
               + int.to_bytes(10, 2, "little")
               + w_size.to_bytes(2, "little")   # Write size
               + address.to_bytes(4, "little")  # Flash address
               + int.to_bytes(frore_utils.fletcher32(data, w_size), 4, 'little')
               + bytes([fc.const['COMM_EOM']]))
    fc.port.write(command)
    time.sleep(1)  # Give FW enough time to write to flash
    response = fc.port.read(6)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for Flash write, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        "Error: Unexpected status in response for COMM_OP_FLASH_PWRITE command, got 0x{:02x}.".format(
            p_res['Status']))
    assert p_res['PayloadLength'] == 0, (
        "Error: Invalid Payload Length in response for COMM_OP_FLASH_PWRITE command, got {}."
        .format(p_res['PayloadLength']))
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Invalid EOM in response for COMM_OP_FLASH_PWRITE command, got 0x{:02x}.".format(p_res['EOM']))

@pytest.mark.regression
def test_comm_op_soft_reset_valid_command(setup_module_scope):
    """
    Test the COMM_OP_SOFT_RESET command.  This command is used for resetting the MCU, not the drive board,
    so data in memory is retained.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    command = [fc.const['COMM_BOM'], fc.const['COMM_OP_SOFT_RESET'], 0, 10, 0, *[0]*10, fc.const['COMM_EOM']]
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Unexpected BOM byte.  Got 0x{:02x}".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        f"Error: Unexpected status for the COMM_OP_SOFT_RESET command. Got {p_res['Status']}.")
    assert p_res['PayloadLength'] == 0, (
        f"Error: Unexpected payload length = 0. Got {p_res['PayloadLength']} ")
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Unexpected EOM byte.  Got 0x{:02x}".format(p_res['EOM']))

@pytest.mark.regression
def test_comm_op_soft_reset_invalid_payload_length(setup_module_scope):
    """
    Test reading a register with an invalid payload length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length read attempt.  Correct payload length is 10 bytes for
    COMM_OP_REG16_READ & COMM_OP_REG32_READ messages, but here we send 14 bytes.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    # Construct a command with invalid payload length (14 instead of 10)
    command = [fc.const['COMM_BOM'], fc.const['COMM_OP_SOFT_RESET'], 0, 14, 0, *[0]*10, fc.const['COMM_EOM']]
    fc.port.write(command)
    response = fc.port.read(fc.const['COMM_RESP_SIZE_DEFAULT'])
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for missing EOM in RAM read, got 0x{:02x}.".format(p_res['Status']))


@pytest.mark.regression
def test_comm_op_enter_app_valid_command(setup_module_scope):
    """
    Test the COMM_OP_ENTER_APP command.  This command is used for transition to application from bootloader.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    command = [fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_APP'], 0, 10, 0, *[0]*10, fc.const['COMM_EOM']]
    fc.port.write(command)
    time.sleep(1)  # Wait for Flash write to complete
    response = fc.port.read(6)
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Unexpected BOM byte.  Got 0x{:02x}".format(p_res['BOM']))
    assert p_res['Status'] == ACK, (
        f"Error: Unexpected status for the COMM_OP_SOFT_RESET command. Got {p_res['Status']}.")
    assert p_res['PayloadLength'] == 0, (
        f"Error: Unexpected payload length = 0. Got {p_res['PayloadLength']} ")
    assert p_res['EOM'] == fc.const['COMM_EOM'], (
        "Error: Unexpected EOM byte.  Got 0x{:02x}".format(p_res['EOM']))
    assert reg16_read(fc, fc.const['REG_SYSTEM_STATUS']) == SystemStatus.APPLICATION.value, (
        "Error: System remains in Bootloader after receiving COMM_OP_ENTER_APP command")

@pytest.mark.regression
def test_comm_op_enter_app_invalid_payload_length(setup_function_scope):
    """
    Test reading a register with an invalid payload length on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the invalid length read attempt.  Correct payload length is 10 bytes for
    COMM_OP_REG16_READ & COMM_OP_REG32_READ messages, but here we send 14 bytes.
    :param setup_function_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_function_scope
    # Construct a command with invalid payload length (14 instead of 10)
    command = [fc.const['COMM_BOM'], fc.const['COMM_OP_ENTER_APP'], 0, 14, 0, *[0]*10, fc.const['COMM_EOM']]
    fc.port.write(command)
    time.sleep(1)
    response = fc.port.read(fc.const['COMM_RESP_SIZE_DEFAULT'])
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Unexpected status in response for missing EOM in COMM_OP_ENTER_APP command. Got 0x{:02x}."
        .format(p_res['Status']))

@pytest.mark.regression
def test_invalid_opcode(setup_module_scope):
    fc, ps = setup_module_scope
    # Construct a command with invalid payload length (14 instead of 10)
    command = [fc.const['COMM_BOM'], 0x50, 0, 14, 0, *[0]*10, fc.const['COMM_EOM']]
    fc.port.write(command)
    response = fc.port.read(fc.const['COMM_RESP_SIZE_DEFAULT'])
    p_res = parse_FroreComm_response(response)
    assert p_res['BOM'] == fc.const['COMM_BOM'], (
        "Error: Invalid BOM in response for RAM read, got 0x{:02x}.".format(p_res['BOM']))
    assert p_res['Status'] == NAK, (
        "Error: Invalid Status in response for missing EOM in RAM read, got 0x{:02x}.".format(p_res['Status']))
