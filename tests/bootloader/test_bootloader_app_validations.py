"""
This file contains test cases for bootloader validation such as app checksum verification,
stay in boot, etc.
"""
import random
import time

import pytest
from pyftdi.i2c import I2cNackError

from Frore_Comm.frore_comm import reflash_section
from tests.conftest import reg16_read, reg32_read, reg16_write, reg32_write, SystemStatus
import Frore_Comm.frore_utils as frore_utils
from tests.utils import *

@pytest.mark.regression
def test_app_checksum_fail(setup_module_scope):
    """
    This test checks that when if the 32-bit checksum flag is set in the OTD section and bootloader fails
    the app checksum, it shall remain in boot.  We will modify the app size in the OTD section so that
    bootloader shall extract incorrect checksum saved in flash thus fails the checksum
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance and power supply.
    """
    fc, ps = setup_module_scope
    # First, get the OTD section from flash then modify needed fields
    ram_addr = 0x20002000
    flash_addr = fc.const['FLASH_OTD_START_ADDR']
    size = fc.const['FLASH_OTD_SIZE']
    otd = fc.flash_dread(flash_addr, size)
    otd[0] = 1      # Set the Verification byte to 32-bit checksum
    otd[8] = 1     # Change the app size
    write_2_ram(fc, ram_addr, otd)
    # Write the OTD section back to flash
    fc.flash_dwrite(flash_addr, size, frore_utils.fletcher32(otd, size))
    time.sleep(1)
    fc.soft_reset()
    time.sleep(1)
    status = fc.reg16_read(fc.const['REG_SYSTEM_STATUS'])
    assert status == SystemStatus.BOOTLOADER.value, (
        f"Error: Unexpected System Status.  Should be in boot mode (0), got {status}"
    )

@pytest.mark.regression
def test_app_checksum_bypass_enabled(setup_module_scope):
    """
    This test checks that when if the 32-bit checksum flag is not set in the OTD section, bootloader
    shall skip the app checksum, and enter application mode.  In the OTD section, we will set the
    Verification byte to 0 and change the app size value.  So when booting up, bootloader shall
    skip the app checksum verification.
    :param setup_module_scope: The setup_module_scope fixture providing the Frore_Comm instance
        and power supply.
    """
    fc, ps = setup_module_scope
    # First, get the OTD section from flash then modify needed fields
    ram_addr = 0x20002000
    flash_addr = fc.const['FLASH_OTD_START_ADDR']
    size = fc.const['FLASH_OTD_SIZE']
    otd = fc.flash_dread(flash_addr, size)
    otd[0] = 0      # Set the Verification byte to 32-bit checksum
    otd[8] = 1     # Change the app size
    write_2_ram(fc, ram_addr, otd)
    # Write the OTD section back to flash
    fc.flash_dwrite(flash_addr, size, frore_utils.fletcher32(otd, size))
    time.sleep(1)
    fc.soft_reset()
    time.sleep(1)
    status = fc.reg16_read(fc.const['REG_SYSTEM_STATUS'])
    assert status == SystemStatus.APPLICATION.value, (
        f"Error: Unexpected System Status.  Should be in App mode (1), got {status}"
    )
