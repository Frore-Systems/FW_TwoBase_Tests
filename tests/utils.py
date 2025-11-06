from typing import Union, Any

from Frore_Comm.frore_comm import FroreComm as FC

ACK = 0x01
NAK = 0x02

def parse_FroreComm_response(response: Union[bytes, list[int]]) -> dict[str, Any]:
    """
    Parse the Frore_Comm response message and return a dictionary with the fields.
    :param response: The response message as bytes.
    :return: A dictionary with the parsed fields.
    """
    result: dict[str, Any] = {
        'BOM': response[0],
        'Status': response[1],
        'Opcode': response[2],
        'Payload': response[5:-1],
        'EOM': response[-1]
    }
    if type(response) == bytes:
        result['PayloadLength'] = int.from_bytes(response[3:5], 'little')
    else:
        result['PayloadLength'] = response[4] << 8 | response[3]
    return result


def read_ram_flash(func, address: int, size: int, checkresponse: bool = False) -> Union[None, list[int]]:
    """
    Fixture to provide a convenient way to read RAM/FLASH from the Frore_Comm device.
    :param func: The FroreComm's ram/flash read function.
    :param address: The RAM/FLASH address to read from.
    :param size: The number of bytes to read.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a RAM address and size and returns the data read from that RAM.
    """
    data = []
    # Read in chunks of 512 bytes (maximum size for RAM/FLASH read per command)
    for i in range(0, size, 512):
        read_size = min(512, size - i)
        # Read the data
        response = func(address + i, read_size, checkresponse)
        p_res = parse_FroreComm_response(response)
        assert p_res['Status'] == ACK, (
            "Error: Invalid Status in response for RAM write before Flash write, got 0x{:02x}.".format(p_res['Status']))
        data += p_res['Payload']
    return data

def write_2_ram(dev: FC, address: int, data: list[int], checkresponse: bool = False) -> None:
    """
    Because each RAM write command can write at most 512 bytes to RAM, so if data is longer than 512 bytes,
    user needs to send multiple RAM write commands.  This function simplifies the write to RAM processes
    RAM_FLASH to the Frore_Comm device.  Maximum 2048 bytes can be writen per call due to RAM limitation.
    :param dev: The Frore_Comm device to write to.
    :param address: The RAM/FLASH address to write to.
    :param data: The data to write as a list of bytes.
    :param checkresponse: Whether to check the response for errors.
    :return: A function that takes a RAM address and data and writes the data to that RAM.
    """
    max_w_size = 512
    w_size = len(data)
    for i in range(0, w_size, max_w_size):
        chunk_size = min(max_w_size, w_size - i)
        chunk_data = data[i:i + chunk_size]
        # Write chunk to RAM
        response = dev.ram_write(address + i, chunk_data, checkresponse)
        p_res = parse_FroreComm_response(response)
        assert p_res['Status'] == ACK, (
            "Error: Invalid Status in response for RAM write, got 0x{:02x}.".format(p_res['Status']))
