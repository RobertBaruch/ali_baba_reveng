# Decodes BOOT2 virtual machine code.

import binascii

DATA = ("04 F2 70 0A F0 70 02 F3 70 06 3D D9 04 F2 70 0A 07 73 01 00 65 02 A3 70 00 D7 70 04 F2 70 07 B3 06 F2 70 00 86 70 04 EA 19 01 5B 25 04 52 19 03 F3 06 03 DD 03 0C 01 AB 25 04 EB 19 03 2C 01 AB 25 03 44 01 AB 25 0C F1 70 0F C2 70 00 A8 70 01 5B 25 01 DE 22 04 52 19 03 89 06 03 DD 03 9E 06 02 DD 06 01 DD 04 EB 19 00 EE 70 09")
ADDR = 0xA985

ADDR_XOR = 0xD903
VAL_XOR = 0x4C

OPCODES = {
    "00": "TJMP",
    "01": "CALL1",
    "02": "TBEQ",
    "03": "LDI",
    "04": "LD",
    "05": "TCALL",
    "06": "ST",
    "07": "SUBI",
    "08": "CALL0",
    "09": "TRET",
    "0A": "LDX",
    "0B": "ASL",
    "0C": "INC",
    "0D": "ADD",
    "0E": "DXR",
    "0F": "TBNE",
    "10": "SUB",
    "11": "COPY",
}
OPTYPES = {
    "00": "addr",
    "01": "addr",
    "02": "addr",
    "03": "val",
    "04": "addr",
    "05": "addr",
    "06": "addr",
    "07": "val",
    "08": "addr",
    "09": "none",
    "0A": "addr",
    "0B": "none",
    "0C": "addr",
    "0D": "val",
    "0E": "none",
    "0F": "addr",
    "10": "addr",
    "11": "none",
}


def main():
    addr = ADDR
    data = DATA.split(" ")
    while data:
        x = data.pop(0)
        print(f"{addr:04X}:   ", end="")
        print(f"{OPCODES[x]:8s}", end="")
        if OPTYPES[x] == "addr":
            a = int(data.pop(0), 16)
            a += int(data.pop(0), 16) << 8
            a ^= ADDR_XOR
            print(f"{a:04X}")
            addr += 3
        elif OPTYPES[x] == "val":
            v = int(data.pop(0), 16)
            v ^= VAL_XOR
            print(f"{v:02X}")
            addr += 2
        else:
            print()
            addr += 1


if __name__ == "__main__":
    main()