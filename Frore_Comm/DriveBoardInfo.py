import struct
from typing import Optional, Union


class DriveBoardInfo:
    BoardGenMapping = {
        2: "TP2",
        3: "PV3",
        4: "BH4"
    }

    BoardTypeMapping = {
        0: "A",
        1: "M",
        2: "B"
    }

    def __init__(self, mdata: Union[bytes, int]) -> None:
        """
        Initialize DriveBoardInfo with a version string.
        The version bytes is expected to be in the that returned from the reg16 or reg32 command.
        """
        if type(mdata) is bytes:
            self.boardrev, tboardtype, tboardcfg, self.boardgen = struct.unpack(">BBBB", mdata)
            self.nochannels = tboardcfg // 10
            self.noboosts = tboardcfg % 10
            self.boardtype = (tboardtype >> 4) & 0x0f
            self.boardtypeno = tboardtype & 0x0F
        else:
            self.boardrev = mdata & 0x0f
            self.boardtype = (mdata >> 12) & 0x0f
            self.boardtypeno = (mdata >> 8) & 0x0f
            tboardcfg = (mdata >> 16) & 0xff
            self.boardgen = (mdata >> 24) & 0x0f
            self.nochannels = tboardcfg // 10
            self.noboosts = tboardcfg % 10

    def __repr__(self):
        """
        Return the version string.
        """
        return '{:s}.{:d}{:d}.{:s}{:d}.R{:d}'.format(self.BoardGenMapping[self.boardgen],
                                                     self.nochannels, self.noboosts,
                                                     self.BoardTypeMapping[self.boardtype], self.boardtypeno,
                                                     self.boardrev)

    def validboardgen(self) -> bool:
        """
        Check if the board generation is valid.
        """
        return self.boardgen in self.BoardGenMapping

    def validboardtype(self) -> bool:
        """
        Check if the board type is valid.
        """
        return self.boardtype in self.BoardTypeMapping


if __name__ ==  "__main__":
    # Example usage
    bdata = bytes([2, 0x12, 0x1f, 0x02])  # Example byte data
    drive_board_info = DriveBoardInfo(bdata)
    print(drive_board_info) # Example output: TP2.31.A2.R2

    bdata = bytes.fromhex('00201504')
    drive_board_info = DriveBoardInfo(bdata)
    print(drive_board_info)

    drive_board_info = DriveBoardInfo(68493312)
    print(drive_board_info)
