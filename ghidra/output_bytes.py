# Outputs byte data for selected area as hex.
# @author Robert Baruch (robert.c.baruch@gmail.com)
# @category Disassembly
# @keybinding ctrl shift PERIOD
# @menupath Tools.Export HexBytes

from ghidra.app.script import GhidraScript
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import Instruction, Data
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register
from ghidra.program.model.address import Address


def run() -> None:
    # ghidra.program.database.code.InstructionDB
    instr = getFirstInstruction()
    mon = monitor()
    listing = currentProgram().getListing()

    if not currentSelection():
        raise ValueError("No selection")

    min_addr = currentSelection().getMinAddress()
    max_addr = currentSelection().getMaxAddress()

    addr = min_addr
    print(f"    {'ORG':9s}${addr.getOffset():04X}")
    while addr.getOffset() <= max_addr.getOffset() and not mon.isCancelled():
        code_unit = listing.getCodeUnitAt(addr)
        if code_unit is None:
            raise ValueError(f"Code unit at {addr} is None")
        bs = code_unit.getBytes()
        for b in bs:
            print(f"{(b&0xFF):02X}", end="")
        addr = addr.add(len(bs))
    print()

run()
