import pytest

from Frore_Comm.DriveBoardInfo import DriveBoardInfo


def test_fw_version(setup, get_setup_config):
    """
    Test the firmware version response from the drive board.
    """
    fc, ps = setup
    response = fc.reg32_read(fc.const['REG_FIRMWARE_VERSION'], False)  # Read the firmware version register
    fwversion = '.'.join(list(map(str, list(reversed(response[5:9])))))
    expected = get_setup_config("Driveboard").get("FWVersion", "Unknown")
    assert fwversion == expected, f"Mismatching firmware version: expected {expected}, got {fwversion}"

def test_hw_version(setup, get_setup_config):
    """
    Test the hardware version response from the drive board.
    """
    fc, ps = setup
    response = fc.reg32_read(fc.const['REG_HARDWARE_VERSION'], True)
    driveboard = DriveBoardInfo(response)
    expected = get_setup_config("Driveboard").get("HWVersion", "Unknown")
    assert str(driveboard) == expected, \
        f"Mismatch Hardware version: expected {expected}, got {str(driveboard)}"

def test_fwbuildno(setup, get_setup_config):
    """
    Test the build number response from the drive board.
    """
    fc, ps = setup

    # Read the firmware build number register
    ifwbuildno = fc.reg32_read(fc.const['REG_FIRMWARE_BUILD_NUMBER'], True) # Read the firmware build number register
    expected = get_setup_config("Driveboard").get("FBN", -1)
    assert expected == ifwbuildno, f"Mismatching FBN number: expected {expected}, got {ifwbuildno}"