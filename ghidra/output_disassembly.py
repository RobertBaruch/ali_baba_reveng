# Outputs disassembly for selected area, only labels and instructions.
# @author Robert Baruch (robert.c.baruch@gmail.com)
# @category Disassembly
# @keybinding ctrl shift COMMA
# @menupath Tools.Export Disassembly

from ghidra.app.script import GhidraScript
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import Instruction, Data
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register
from ghidra.program.model.address import Address


def print_data(data: Data) -> None:
    if data.isArray():
        for i in range(data.getNumComponents()):
            sub_data = data.getComponent(i)
            print_data(sub_data)
        return
    data_type_len = data.getDataType().getLength()
    data_type = data.getDataType().getDisplayName()

    if isinstance(data.getValue(), Scalar):
        value = data.getValue().getValue()
    elif isinstance(data.getValue(), Address):
        value = data.getValue().getOffset()
    elif isinstance(data.getValue(), str):  # data_type 'char'
        # Just one character should be present.
        if len(bytes(data.getValue(), "utf-8")) != 1:
            raise ValueError(f"String data value is not a single character: {data.getValue()}")
        value = ord(data.getValue()[0])
    else:
        raise ValueError(f"Unknown data value type for data type {data_type}: {type(data.getValue())}")

    if data.isPointer():
        symbol = getSymbolAt(data.getValue())
        if symbol is not None:
            print(f"    {'WORD':9s}{symbol}")
        else:
            print(f"    {'WORD':9s}{(value&0xFFFF):04X}")
    elif data_type_len == 1:
        print(f"    {'BYTE':9s}{(value&0xFF):02X}")
    elif data_type_len == 2:
        print(f"    {'WORD':9s}{(value&0xFFFF):04X}")
    elif data_type_len == 4:
        print(f"    {'LONG':9s}{(value&0xFFFFFFFF):08X}")
    else:
        raise ValueError(f"Unknown data type: {data_type}")

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
        label = code_unit.getLabel()
        if label:
            print(f"{label}:")
        if isinstance(code_unit, Instruction):
            instr = code_unit
            mnemonic = instr.getMnemonicString()
            # 6502 instructions have either 0 operands or 1 operand.
            num_operands = instr.getNumOperands()
            s = ""
            for i in range(num_operands):
                optype = instr.getOperandType(i)
                op_addr = instr.getAddress(i)
                # print(f"  operand {i}: {OperandType.toString(optype)}")
                op_addr_sym = None if not op_addr else str(getSymbolAt(op_addr))
                for o in instr.getDefaultOperandRepresentationList(i):
                    if isinstance(o, str):
                        s += o
                    elif isinstance(o, Scalar):
                        s += op_addr_sym if op_addr_sym else f"${o.getValue():02X}"
                    elif isinstance(o, Address):
                        s += op_addr_sym if op_addr_sym else f"${o.getOffset():04X}"
                    elif isinstance(o, Register):
                        s += str(o)
                    else:
                        raise ValueError(
                            f"    {s}... unknown operand part: <{type(o)}>{o}"
                        )
                # if op_addr_sym:
                #     print(f"    address -> {op_addr_sym}")
            print(f"    {mnemonic:9s}{s}")
            addr = addr.add(instr.getLength())
            # print(f"  next addr: {addr}")

        elif isinstance(code_unit, Data):
            print_data(code_unit)
            addr = addr.add(code_unit.getLength())


run()

# for func in currentProgram().getListing().getFunctions(True):
#     block_count = 0

#     # find basic block count for the current function
#     block_itr = SimpleBlockIterator(
#         BasicBlockModel(currentProgram()), func.getBody(), monitor()
#     )
#     while block_itr.hasNext():
#         block_count += 1
#         block_itr.next()

#     # find instruction count for the current function
#     insn_count = len(
#         tuple(currentProgram().getListing().getInstructions(func.getBody(), True))
#     )

#     # print counts to user
#     print(
#         f"Function {func.getName()} @ {hex(func.getEntryPoint().getOffset())}: {block_count} blocks, {insn_count} instructions"
#     )
