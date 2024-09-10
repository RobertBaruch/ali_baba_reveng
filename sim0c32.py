"""Simulates function at 0x0C32."""

from absl import app


def rol(value: int) -> int:
    """8-bit rotate left through carry.

    The carry flag is in bit 8 of the input and output values.
    """
    value &= 0x1FF
    return ((value << 1) | (value >> 8)) & 0x1FF


def compute(a: int) -> int:
    """Simulates function at 0x0C32.

    FUN_0c32:
        CLC
        ADC      #$FF
        ROL      A
        ROL      A
        ROL      A
        ROL      A
        TAY
        ROL      A
        AND      #$0F
        CLC
        ADC      CONST_DAT_4001
        STA      DATA_PTR3+1
        TYA
        AND      #$F0
        CLC
        ADC      CONST_DAT_4000
        STA      DATA_PTR3
        BCC      LAB_0c50
        INC      DATA_PTR3+1
    LAB_0c50:
        RTS
    """
    const_dat_4001 = 0x4C
    const_dat_4000 = 0x80
    ptr = 0

    a = (a + 0xFF) & 0x1FF
    a = rol(rol(rol(rol(a))))
    y = a & 0xFF

    a = rol(a)
    a &= 0x0F
    a = (a + const_dat_4001) & 0xFF
    ptr = a << 8

    a = y
    a &= 0xF0
    ptr += a + const_dat_4000
    return ptr


def main(argv: list[str]) -> None:
    if len(argv) > 1:
        raise app.UsageError("Too many command-line arguments.")
    for a in range(256):
        ptr = compute(a)
        print(f"{a:02X} -> {ptr:04X}")


if __name__ == "__main__":
    app.run(main)
