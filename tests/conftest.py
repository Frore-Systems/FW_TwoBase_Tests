import json
from enum import IntEnum
from typing import Optional, Any

from Frore_Comm.frore_comm import FroreComm
import pytest
import libsqa.dev.kiprim.kiprim_backend as kb

SETUPCFG: dict[str: Any] = {}     # Global variable to hold the setup configuration
CONST_JSON_FILE = "frore_const.json"  # Default constants file

class SystemStatus(IntEnum):
    BOOTLOADER = 0
    APPLICATION = 1

@pytest.fixture(scope="session")
def get_setup_config():
    """
    Get the global setup configuration dictionary.
    """
    def _get_setup_config(key: str):
        global SETUPCFG
        return SETUPCFG.get(key, None)
    return _get_setup_config

def parse_devices_setup(setupjsfile: str) -> dict:
    """
    Parse the setupjsfile file to extract device information.  This file is a JSON
    formatted file containing a list of devices with their properties.
    """
    import json

    with open(setupjsfile, 'r') as f:
        cfg = json.load(f)
    return cfg

def pytest_addoption(parser):
    parser.addoption("--setupcfg", action="store", default="devices_setup.json", help="Device setup JSON file")

@pytest.fixture(scope="session", autouse=True)
def setup(request):
    """
    Setup function to initialize the test environment.  It reads device configuration
    from a JSON file specified by the --devconfig command line option.  It initializes
    the FroreComm instance and a power supply instance.  The power supply is turned on
    before the FroreComm instance is created and turned off after the tests are done.
    The power supply is assumed to be a Kiprim power supply.  The FroreComm instance
    is created using the COM port specified in the JSON file.  The fixture yields a tuple
    containing the FroreComm instance and the power supply instance.  Function yields
    power supply to allow tests to modify its state if needed.
    :param request: pytest request object to access command line options.
    :return: A tuple containing the FroreComm instance and the power supply instance.
    """
    setupcfgfile = request.config.getoption("--setupcfg")
    global SETUPCFG, CONST_JSON_FILE
    SETUPCFG = parse_devices_setup(setupcfgfile)

    # This function can be used to set up any necessary state before tests run
    fc: Optional[FroreComm, None] = None
    ps : Optional[kb.Kiprim, None] = None

    try:
        ps = kb.open(SETUPCFG["PowerSupply"])
        kb.set(ps, 5.0, 1.0)
        kb.on(ps)

        with open(CONST_JSON_FILE, 'r') as f:
            consts = json.load(f)
        fc: FroreComm = FroreComm(SETUPCFG["Driveboard"].get("COM", None), const=consts)

        if fc.url is None:
            raise ValueError("No device found. Please connect a Frore driveboard device.")
        fc.open()  # Open the device connection

        # Make sure that device is in bootloader mode
        if fc.reg16_read(fc.const['REG_SYSTEM_STATUS'], True) != SystemStatus.BOOTLOADER.value:
            fc.enter_boot()

        if fc.reg16_read(fc.const['REG_SYSTEM_STATUS'], True) != SystemStatus.BOOTLOADER.value:
            raise ValueError("Device is not in bootloader mode. Please reset the device and try again.")

        yield fc, ps # This will be used in tests

    except Exception as e:
        pytest.fail(f"Setup failed: {e}")
    finally:
        fc.close()  # Close the device connection after tests are done
        del fc, consts
        kb.off(ps)
        kb.close(ps)
        del ps
