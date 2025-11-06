import json
import time
from enum import IntEnum
from typing import Optional, Union

from Frore_Comm.frore_comm import FroreComm
import pytest
import libsqa.dev.kiprim.kiprim_backend as kb

SETUPCFG: dict = {}     # Global variable to hold the setup configuration
CONST_JSON_FILE = "frore_const.json"  # Default constants file
PWRITE_TEST_FILE = "test_data/flash_pwrite_test_data.pkg"

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


def _setup(request):
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

        try:
            # Make sure that device is in bootloader mode
            if fc.reg16_read(fc.const['REG_SYSTEM_STATUS'], True) != SystemStatus.BOOTLOADER.value:
                fc.enter_boot()
        except Exception as e:
            raise ConnectionError(f"Drive board is not connected or not responding: {e}")

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

@pytest.fixture(scope="session", autouse=False)
def setup_session_scope(request):
    """
    Session scoped setup fixture to initialize the test environment.
    This fixture runs once per test session.
    :param request: pytest request object to access command line options.
    :return: A tuple containing the FroreComm instance and the power supply instance.
    """
    yield from _setup(request)

@pytest.fixture(scope="function", autouse=False)
def setup_function_scope(request):
    """
    Function scoped setup fixture to initialize the test environment.
    This fixture runs once per test function.
    :param request: pytest request object to access command line options.
    :return: A tuple containing the FroreComm instance and the power supply instance.
    """
    yield from _setup(request)
    time.sleep(0.8)

@pytest.fixture(scope="module", autouse=False)
def setup_module_scope(request):
    """
    Function scoped setup fixture to initialize the test environment.
    This fixture runs once per test function.
    :param request: pytest request object to access command line options.
    :return: A tuple containing the FroreComm instance and the power supply instance.
    """
    yield from _setup(request)
    time.sleep(0.5)

def reg16_read(fc: FroreComm, registerid: int, checkresponse: bool = True) -> Union[None, list[int]]:
    """
    Fixture to provide a convenient way to read 16-bit registers from the Frore_Comm device.
    :param fc: The Frore_Comm instance.
    :param registerid: The register index to read.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a register index and returns the 16-bit value read from that register.
    """
    return fc.reg16_read(registerid, checkresponse)


def reg32_read(fc: FroreComm, registerid: int, checkresponse: bool = True) -> Union[None, list[int]]:
    """
    Fixture to provide a convenient way to read 32-bit registers from the Frore_Comm device.
    :param fc: The Frore_Comm instance.
    :param registerid: The register index to read.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a register index and returns the 32-bit value read from that register.
    """
    return fc.reg32_read(registerid, checkresponse)

def reg16_write(fc: FroreComm, registerid: int, value: int, checkresponse: bool = True) -> Union[None, list[int]]:
    """
    Fixture to provide a convenient way to write 16-bit registers to the Frore_Comm device.
    :param fc: The Frore_Comm instance.
    :param registerid: The register index to read.
    :param value: The 16-bit value to write to the register.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a register index and a 16-bit value to write to that register.
    """
    return fc.reg16_write(registerid, value, checkresponse)

def reg32_write(fc: FroreComm, registerid: int, value: int, checkresponse: bool = True) -> Union[None, list[int]]:
    """
    Fixture to provide a convenient way to write 32-bit registers to the Frore_Comm device.
    :param fc: The Frore_Comm instance.
    :param registerid: The register index to read.
    :param value: The 32-bit value to write to the register.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a register index and a 32-bit value to write to that register.
    """
    return fc.reg32_write(registerid, value, checkresponse)

@pytest.fixture
def operation(request):
    # request.param will be the function passed from parametrize
    return request.param

@pytest.fixture
def setup_pwrite_data():
    with open(PWRITE_TEST_FILE, 'rb') as f:
        data = f.read()
    yield data
    del data