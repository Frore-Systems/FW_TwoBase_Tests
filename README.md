This repository contains all FW test scripts for the Frore - FW TwoBase, including bootloader, application, etc.  Pytest automation framework is used for developing and running test scripts.
The FW_TwoBase_Tests requires Frore - libSQA package to control peripherals (such as power supply, heater, etc.).  

Folder structure:
Frore_Comm/
  - __init__.py
  - DriveBoardInfo.py
  - frore_comm.py
  - frore_parse.py
  - frore_utils.py
tests/
  - application/
    - __init__.py
    - frore_const.json
    - test_driveboardmodes
      ... 
  - bootloader/
    - __init__.py
    - test_frore_comm.py
    - test_driveboardinfo.py
      ...
  - __init.py__
  - conftest.py
  - devices_setup.json
  - frore_config.json
  - frore_const.json
README.md

**Frore_Comm** folder contains some modules (frore_comm.py, frore_utils.py, etc.) imported from Firmware-Twobase/test, that contains Frore Communication protocol and utilities used for 
communicating to the drive board (Bayhill and/or future platform). These modules are modified in order to run the test scripts.  User needs to ensure that these modules are up to date
before running the tests between versions.
**tests** folder contains test scripts for the Firmware TwoBase
  - **bootloader** folder contains bootloader test scripts
  - **application** folder contains application test scripts
Each test script can contain one or more tests

conftest.py contains the test fixtures and utilities to run the tests
devices_setup.json contains the peripherals such as power supply and driveboard information (e.g. HW & FW Version, FBN, COM Port, tc.)
frore_config.json contains information about the registers of the firmware.
frore_const.json contains contants information of the Flash, RAM, registers, etc.  Frore_Comm uses it to determine the memory address of the Flash, RAM, or register ids, etc.  This file
contains a subset of the frore_const.json in the application folder.  This file is used for running the bootloader tests.  Application uses application/frore_const.json for application
tests.


-------------
INSTALLATION:
1. pip install -r requirements.txt
2. Install libSQA package in the root folder
3. Update modules Frore_Comm folder with changes in the firmware.

------------
RUN TESTS:
1. cd tests
2. Run tests
   - Bootloader: pytest -v -l .\bootloader
   - Application: pytest -v -l .\bootloader
   - All tests: pytest -v -l
   To generate html report for the test run, add "--html=<_reportfile.html_>" to the pytest command.  The _reportfile.html_ contains details report of the run.


