import pytest


@pytest.mark.parametrize("registerid", [0xffff, 1000, 12])
def test_read_invalid_registers(setup, registerid):
    """
    Test reading an invalid register from the Frore_Comm device.  Drive board should
    respond with an ACK without data (0) for the invalid register read attempt.
    As of 2.6.0.0, even though the register is invalid (for example, register 12) and in
    the valid range of registers, the device responds with ACK and some data.  This is
    considered acceptable behavior.  Only test with boundary of the registers range
    :param registerid: Register id to be tested.
    """
    fc, ps = setup
    response = fc.reg16_read(registerid, False)
    assert response[1] == 1, \
        f"Expected ACK (0x01) for invalid register read, got {response[1]} for register ID {registerid}."

def test_write_invalid_registers(setup):
    """
    Test writing to an invalid register on the Frore_Comm device.  Drive board should
    respond with a NAK (0xFF) for the invalid register write attempt.
    :param setup: The setup fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup
    response = fc.reg16_write(0xffff, 1234, False)
    assert response[1] == 0x02, "Error: Expected NAK (0x02) for invalid register write, got {response[1]}."

@pytest.mark.regression
@pytest.mark.parametrize("registerid", ['REG_FIRMWARE_VERSION', 'REG_HARDWARE_VERSION',
                                        'REG_FIRMWARE_BUILD_NUMBER', 'REG_FLASH_COPY_ADDR',
                                        'REG_PRODUCT_NAME_ADDR', 'REG_REGISTER_ADDR',
                                        'REG_SERIAL_NUMBER'] )
def test_write_readonly_registers(setup, registerid):
    """
    Test writing to a read-only register on the Frore_Comm device.  Drive board should
    respond with a NAK (0x02) for the read-only register write attempt.
    :param setup: The setup fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup
    reg = fc.const[registerid]
    #response = fc.reg32_read(register)
    response = fc.reg16_write(reg, 1234, False)
    assert response[1] == 0x02, f"Error: Expected NAK (0x02) for read-only register write to {reg}, got {response[1]}."




