import binascii
import io


def swaplowbits(x: int) -> int:
    return ((x & 0x01) << 1) | ((x & 0x02) >> 1)


def prenibblize(data: bytes) -> tuple[bytes, bytes]:
    """Implements the standard DOS 3.3 6-and-2 prenibblize algorithm.

    Returns:
      A tuple of the primary and secondary buffers.
    """
    primary = bytearray(256)
    secondary = bytearray(86)

    for i in range(256):
        primary[i] = (data[i] >> 2) & 0x3F
    for i in range(86):
        index = 0x55 - i
        secondary[i] = swaplowbits(data[index])
        index = 0xAB - i
        secondary[i] |= swaplowbits(data[index]) << 2
        index = (0x101 - i) & 0xFF
        secondary[i] |= swaplowbits(data[index]) << 4
    secondary[0] &= 0x0F  # Remove the duplicated bits
    secondary[1] &= 0x0F

    return primary, secondary


def standard_data_to_disk2(data: bytes) -> bytes:
    nibbles = bytearray(342)
    offset = 0xAC
    nibbleptr = 0

    value = 0
    def add_value(a: int) -> None:
        nonlocal value
        value = (value << 2) | ((a & 0x01) << 1) | ((a & 0x02) >> 1)

    while offset != 0x02:
        value = 0
        add_value(data[offset])
        offset = (offset - 0x56) & 0xFF
        add_value(data[offset])
        offset = (offset - 0x56) & 0xFF
        add_value(data[offset])
        offset = (offset - 0x53) & 0xFF
        nibbles[nibbleptr] = value # << 2
        nibbleptr += 1
    nibbles[nibbleptr-2] &= 0x0F # 0x3F
    nibbles[nibbleptr-1] &= 0x0F # 0x3F
    print(f"v2 secondary: {binascii.hexlify(nibbles)}")
    for loop in range(0x100):
        nibbles[nibbleptr] = data[loop]
        nibbleptr += 1

    savedval = 0
    srcptr = 0
    resultptr = 0
    result = bytearray(343)
    for _ in range(341, -1, -1):
        result[resultptr] = savedval ^ nibbles[srcptr]
        resultptr += 1
        savedval = nibbles[srcptr]
        srcptr += 1
    result[resultptr] = savedval

    return nibbles


def standard_data_to_disk(data: bytes) -> bytes:
    """Implements the standard DOS 3.3 6-and-2 encoded disk write."""
    primary, secondary = prenibblize(data)

    stream = io.BytesIO()
    write_byte = lambda x: stream.write(bytes([x]))

    write_translate = binascii.unhexlify(
        "".join(
            [
                "96979A9B9D9E9F",
                "A6A7ABACADAEAF",
                "B2B3B4B5B6B7B9BABBBCBDBEBF",
                "CBCDCECF",
                "D3D6D7D9DADBDCDDDEDF",
                "E5E6E7E9EAEBECEDEEEF",
                "F2F3F4F5F6F7F9FAFBFCFDFEFF",
            ]
        )
    )
    # Write the first 86 bytes:
    # prev xor curr:
    # 0 xor secondary[85]
    # secondary[85] xor secondary[84]
    # ...
    # secondary[1] xor secondary[0]
    prev = 0
    curr = 0
    for y in range(0x55, -1, -1):
        prev, curr = curr, secondary[y]
        x = prev ^ curr
        write_byte(write_translate[x])

    # Write the rest.
    # prev xor curr:
    # secondary[0] xor primary[0]
    # primary[0] xor primary[1]
    # ...
    # prumary[254] xor primary[255]
    for y in range(256):
        prev, curr = curr, primary[y]
        x = prev ^ curr
        write_byte(write_translate[x])

    # Write the "checksum"
    write_byte(write_translate[primary[0xFF]])
    return stream.getvalue()


def postnibblize(primary: bytes, secondary: bytes) -> bytes:
    """Implements the standard DOS 3.3 6-and-2 postnibblize algorithm."""
    data = bytearray(256)

    for i in range(256):
        data[i] = primary[i] << 2
    for i in range(86):
        index = 0x55 - i
        data[index] |= swaplowbits(secondary[i] & 0x03)
        index = 0xAB - i
        data[index] |= swaplowbits((secondary[i] & 0x0C) >> 2)
        index = (0x101 - i) & 0xFF
        data[index] |= swaplowbits((secondary[i] & 0x30) >> 4)

    return bytes(data)


def standard_disk_to_data(data: bytes) -> bytes:
    """Implements the standard DOS 3.3 6-and-2 encoded disk read."""
    stream = io.BytesIO(data)
    read_byte = lambda: stream.read(1)[0]

    primary = bytearray(256)
    secondary = bytearray(86)
    read_translate = binascii.unhexlify(
        "".join(
            [
                "0001",
                "9899",
                "0203",
                "9C",
                "040506",
                "A0A1A2A3A4A5",
                "0708",
                "A8A9AA",
                "090A0B0C0D",
                "B0B1",
                "0E0F10111213",
                "B8",
                "1415161718191A",
                "C0C1C2C3C4C5C6C7C8C9CA",
                "1B",
                "CC",
                "1C1D1E",
                "D0D1D2",
                "1F",
                "D4D5",
                "2021",
                "D8",
                "22232425262728",
                "E0E1E2E3E4",
                "292A2B",
                "E8",
                "2C2D2E2F303132",
                "F0F1",
                "333435363738",
                "F8",
                "393A3B3C3D3E3F",
            ]
        )
    )

    a = 0

    # Do for y=0x55 down to y=0.
    for y in range(0x55, -1, -1):
        b = read_byte()
        a ^= read_translate[b - 0x96]
        secondary[y] = a

    for y in range(256):
        b = read_byte()
        a ^= read_translate[b - 0x96]
        primary[y] = a

    b = read_byte()
    if read_translate[b - 0x96] != a:
        print("Checksum failed")

    return postnibblize(primary, secondary)


def ea_disk_to_data(data: bytes) -> bytes:
    """Implements EA's 6-and-2 encoded disk read."""
    print(f"data len = {len(data)}")
    stream = io.BytesIO(data)
    read_byte = lambda: stream.read(1)[0]

    # This seems to be the same as the DOS 3.3 table, except the data
    # is shifted left by 2.
    read_translate = binascii.unhexlify(
        "".join(
            [
                "0004",
                "9899",
                "080C",
                "9C",
                "101418",
                "A0A1A2A3A4A5",
                "1C20",
                "A8A9AA",
                "24282C3034",
                "B0B1",
                "383C4044484C",
                "B8",
                "5054585C606468",
                "C0C1C2C3C4C5C6C7C8C9CA",
                "6C",
                "CC",
                "707478",
                "D0D1D2",
                "7C",
                "D4D5",
                "8084",
                "D8",
                "888C9094989CA0",
                "E0E1E2E3E4",
                "A4A8AC",
                "E8",
                "B0B4B8BCC0C4C8",
                "F0F1",
                "CCD0D4D8DCE0",
                "F8",
                "E4E8ECF0F4F8FC",
            ]
        )
    )

    decrypt_table = binascii.unhexlify("".join([
        "00000096",
        "02000097",
        "0100009A",
        "0300009B",
        "0002009D",
        "0202009E",
        "0102009F",
        "030200A6",
        "000100A7",
        "020100AB",
        "010100AC",
        "030100AD",
        "000300AE",
        "020300AF",
        "010300B2",
        "030300B3",
        "000002B4",
        "020002B5",
        "010002B6",
        "030002B7",
        "000202B9",
        "020202BA",
        "010202BB",
        "030202BC",
        "000102BD",
        "020102BE",
        "010102BF",
        "030102CB",
        "000302CD",
        "020302CE",
        "010302CF",
        "030302D3",
        "000001D6",
        "020001D7",
        "010001D9",
        "030001DA",
        "000201DB",
        "020201DC",
        "010201DD",
        "030201DE",
        "000101DF",
        "020101E5",
        "010101E6",
        "030101E7",
        "000301E9",
        "020301EA",
        "010301EB",
        "030301EC",
        "000003ED",
        "020003EE",
        "010003EF",
        "030003F2",
        "000203F3",
        "020203F4",
        "010203F5",
        "030203F6",
        "000103F7",
        "020103F9",
        "010103FA",
        "030103FB",
        "000303FC",
        "020303FD",
        "010303FE",
        "030303FF",
    ]))

    tmp = bytearray(256)
    buff = bytearray(256)

    # Part 1
    a = 0
    for y in range(0xAA, 0x100):
        scratch = a
        a = read_translate[read_byte() - 0x96]
        tmp[y] = a
        a ^= scratch

    print(binascii.hexlify(tmp[0xAA:]))
    print(f"{a=:02X}")

    # Part 2
    for y in range(0xAA, 0x100):
        if y != 0xAA:
            # print(f"buff[{y-0xAB}] = {a:02X}")
            buff[y-0xAB] = a
        a ^= read_translate[read_byte() - 0x96]
        x = tmp[y]
        a ^= decrypt_table[x]

    print("--------------------")
    # Part 3
    save_a = a
    a &= 0xFC
    for y in range(0xAA, 0x100):
        a ^= read_translate[read_byte() - 0x96]
        x = tmp[y]
        a ^= decrypt_table[x + 1]
        # print(f"buff[{y - 0xAA + 85}] = {a:02X}")
        buff[y - 0xAA + 85] = a

    print("--------------------")
    # Part 4
    x = read_byte()
    a &= 0xFC
    y = 0xAC

    for y in range(0xAC, 0x100):
        a ^= read_translate[x - 0x96]
        x = tmp[(y+0x100-2)&0xFF]
        a ^= decrypt_table[x + 2]
        # print(f"buff[{y-0xAC+172}] = {a:02X}")
        buff[y-0xAC+172] = a
        x = read_byte()

    a &= 0xFC
    a ^= read_translate[x - 0x96]
    x = 0x60
    y = a
    print(f"{a=:02X} {x=:02X} {y=:02X}")
    if a != 0:
        print("Decrypt failed")
    return buff




def main() -> None:
    with io.open("t7s0.bin", "rb") as file:
        data = file.read()
    print(f"Sector data: {binascii.hexlify(data)}")

    # First we convert to 342 bytes of standard DOS 6-and-2 encoding, plus a one-byte
    # checksum, as if we were writing to a disk.
    disk_data = standard_data_to_disk(data)
    print(f"Disk data: {binascii.hexlify(disk_data)}")

    # We verify that the disk data is correct by "reading" it back in standard
    # DOS 6-and-2 encoding.
    read_data = standard_disk_to_data(disk_data)
    if read_data != data:
        print("Read data does not match original data")
        print(f"Sector data: {binascii.hexlify(read_data)}")

    # However, we have to read the disk using EA's decryption.
    buff = ea_disk_to_data(disk_data)
    print(f"Buff: {binascii.hexlify(buff)}")

if __name__ == "__main__":
    main()
