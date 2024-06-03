import bitstring
from pyvex.lifting.util import *
from pyvex.lifting import register


# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017
# Rewrote by edg for gymrat on 9/4/2017
# The goal of this, and any other lifter, is to convert one basic block of raw bytes into
# a set of VEX instructions representing what the code does.
# A basic block, in this case is defined a set of instructions terminated by:
# !) a conditional branch
# 2) A function call
# 3) A system call
# 4) the end of the program
#
# We need to build an IRSB, a grouping of VEX code, and associated metadata representing one block.
# This is then used by angr itself to perform static analysis and symbolic execution.

##
# These helper functions are how we resolve jumps in VMWHERE.
# Because they require scanning the actual code to resolve, they require a global view of the program's memory.
# Lifters in pyvex only get block-at-a-time access to memory, so we solve this by using a "CCall", which tells VEX
# /angr to execute a side-effect-less function and put the result in a variable.
# We therefore let angr resolve all jumps at "run"-time.
# TODO: FIXME: We need to refactor CCall to be more friendly to adding CCalls.  I will document the process here as best I can.


# For the sake of my sanity, the ptr is 64 bits wide.
# By the spec, cells are 8 bits, and do all the usual wrapping stuff.
PTR_TYPE = Type.int_64
STACK_ENTRY_TYPE = Type.int_8
SP_REG = 'sp'
BP_REG = 'bp'
SYSNUM_REG = 'sysnum'


class VMWHEREInstruction(Instruction):
    def disassemble(self):
        arg = self.rawbits[2:]
        if arg:
            arg = int(self.rawbits[2:], 16)
            arg = hex(arg)
        return self.addr, self.name, [arg]


class Instruction_EXIT(VMWHEREInstruction):

    bin_format = bin(0x0)[2:].zfill(8)
    name = 'exit'

    def parse(self, bitstrm):
        self.last_instruction = False
        data = VMWHEREInstruction.parse(self, bitstrm)
        try:
            bitstrm.peek(8)
        except bitstring.ReadError:
            # We ran off the end!
            self.last_instruction = True
        return data

    def compute_result(self, *args):
        # assert(self.last_instruction == True)
        self.jump(None, self.constant(self.addr, PTR_TYPE), jumpkind=JumpKind.Exit)


class Instruction_ADD(VMWHEREInstruction):

    bin_format = bin(0x1)[2:].zfill(8)
    name = 'add'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(a + b)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b + a
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_SUB(VMWHEREInstruction):

    bin_format = bin(0x2)[2:].zfill(8)
    name = 'sub'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(b - a)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b - a
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_AND(VMWHEREInstruction):

    bin_format = bin(0x3)[2:].zfill(8)
    name = 'and'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(a & b)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b & a
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_OR(VMWHEREInstruction):

    bin_format = bin(0x4)[2:].zfill(8)
    name = 'or'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(a | b)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b | a
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_XOR(VMWHEREInstruction):

    bin_format = bin(0x5)[2:].zfill(8)
    name = 'xor'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(a ^ b)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b ^ a
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_SHL(VMWHEREInstruction):

    bin_format = bin(0x6)[2:].zfill(8)
    name = 'shl'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(b << (a & 0x1f))
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b << (a & 0x1f)
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_SHR(VMWHEREInstruction):

    bin_format = bin(0x7)[2:].zfill(8)
    name = 'shr'

    def compute_result(self, *args):
        """
        a = pop()
        b = pop()
        push(b >> (a & 0x1f))
        """
        sp = self.get(SP_REG, PTR_TYPE)
        a = self.load(sp - 1, STACK_ENTRY_TYPE)
        b = self.load(sp - 2, STACK_ENTRY_TYPE)
        b = b >> (a & 0x1f)
        self.store(b, sp - 2)
        self.put(sp - 1, SP_REG)


class Instruction_READ(VMWHEREInstruction):

    bin_format = bin(0x8)[2:].zfill(8)
    name = 'read'

    def compute_result(self, *args):
        """
        k = getchar()
        push((byte)k)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        self.put(sp + 1, SP_REG)

        self.put(self.constant(0, PTR_TYPE), SYSNUM_REG)
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


class Instruction_WRITE(VMWHEREInstruction):

    bin_format = bin(0x9)[2:].zfill(8)
    name = 'write'

    def compute_result(self, *args):
        """
        k = pop()
        putchar(k)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        self.put(sp - 1, SP_REG)

        self.put(self.constant(1, PTR_TYPE), SYSNUM_REG)
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


class Instruction_PUSH(VMWHEREInstruction):

    bin_format = bin(0xa)[2:].zfill(8) + 'x' * 8
    name = 'push'

    def compute_result(self, *args):
        """
        arg: x
        push(x)
        """
        x = self.constant(int(self.data['x'], 2), STACK_ENTRY_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)
        self.store(x, sp)
        self.put(sp + 1, SP_REG)

    def disassemble(self):
        arg = bytes.fromhex(self.rawbits[2:])
        return self.addr, self.name, [arg]


class Instruction_JLZ(VMWHEREInstruction):

    bin_format = bin(0xb)[2:].zfill(8) + 'x' * 16
    name = 'jlz'

    def compute_result(self, *args):
        """
        arg: xx
        if top() < 0: jmp + xx
        """
        jump_offset = int(self.data['x'], 2)
        dst = self.constant(self.addr + 3 + jump_offset, Type.int_16)

        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp - 1, STACK_ENTRY_TYPE).signed
        zero = self.constant(0, STACK_ENTRY_TYPE)

        self.jump(top < zero, dst)

    def disassemble(self):
        arg = int(self.rawbits[2:], 16)
        if arg & (0x8000):
            offset = arg - 0xffff - 1
        else:
            offset = arg
        jmp = self.addr + 3 + offset
        return self.addr, self.name, [hex(jmp), jmp, offset]


class Instruction_JZ(VMWHEREInstruction):

    bin_format = bin(0xc)[2:].zfill(8) + 'x' * 16
    name = 'jz'

    def compute_result(self, *args):
        """
        arg: xx
        if top() == 0: jmp + xx
        """
        jump_offset = int(self.data['x'], 2)
        dst = self.constant(self.addr + 3 + jump_offset, Type.int_16)

        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp - 1, STACK_ENTRY_TYPE).signed
        zero = self.constant(0, STACK_ENTRY_TYPE)

        self.jump(top == zero, dst)

    def disassemble(self):
        arg = int(self.rawbits[2:], 16)
        if arg & (0x8000):
            offset = arg - 0xffff - 1
        else:
            offset = arg
        jmp = self.addr + 3 + offset
        return self.addr, self.name, [hex(jmp), jmp, offset]


class Instruction_JMP(VMWHEREInstruction):

    bin_format = bin(0xd)[2:].zfill(8) + 'x' * 16
    name = 'jmp'

    def compute_result(self, *args):
        """
        arg: xx
        jmp + xx
        """
        jump_offset = int(self.data['x'], 2)
        dst = self.constant(self.addr + 3 + jump_offset, Type.int_16)
        self.jump(None, dst)

    def disassemble(self):
        arg = int(self.rawbits[2:], 16)
        if arg & (0x8000):
            offset = arg - 0xffff - 1
        else:
            offset = arg
        jmp = self.addr + 3 + offset
        return self.addr, self.name, [hex(jmp), jmp, offset]


class Instruction_POP(VMWHEREInstruction):

    bin_format = bin(0xe)[2:].zfill(8)
    name = 'pop'

    def compute_result(self, *args):
        """
        pop()
        """
        sp = self.get(SP_REG, PTR_TYPE)
        self.put(sp - 1, SP_REG)


class Instruction_PUSHSTK(VMWHEREInstruction):

    bin_format = bin(0xf)[2:].zfill(8)
    name = 'pushstk'

    def compute_result(self, *args):
        """
        push(top())
        """
        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp - 1, STACK_ENTRY_TYPE)
        self.store(top, sp)
        self.put(sp + 1, SP_REG)


class Instruction_REV(VMWHEREInstruction):

    bin_format = bin(0x10)[2:].zfill(8) + 'x' * 8
    name = 'rev'

    def compute_result(self, *args):
        """
        arg: x
        stk.reverse(SP_REG - 1, SP_REG - x - 1)
        """
        offset = int(self.data['x'], 2)
        sp = self.get(SP_REG, PTR_TYPE)
        bp = self.get(BP_REG, PTR_TYPE)
        for i in range(offset // 2):
            b = self.load(sp + i - offset, STACK_ENTRY_TYPE)
            a = self.load(sp + (~i), STACK_ENTRY_TYPE)
            self.store(a, sp + i - offset)
            self.store(b, sp + (~i))

        self.jump((sp - bp) < self.constant(offset, PTR_TYPE),
                  self.constant(0, PTR_TYPE))
        self.jump(None, self.constant(0, PTR_TYPE), JumpKind.Segfault)


class Instruction_EXP(VMWHEREInstruction):

    bin_format = bin(0x11)[2:].zfill(8)
    name = 'exp'

    def compute_result(self, *args):
        """
        val = top()
        push(val & (1 << 0))
        push(val & (1 << 1))
        ...
        push(val & (1 << 7))
        """
        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp - 1, STACK_ENTRY_TYPE)
        for i in range(8):
            self.store(top & 1, sp - 1 + i)
            top = top >> 1
        self.put(sp + 7, SP_REG)


class Instruction_SQZ(VMWHEREInstruction):

    bin_format = bin(0x12)[2:].zfill(8)
    name = 'sqz'

    def compute_result(self, *args):
        """
        val = 0
        val = val | (top() & 1)
        pop()
        ... x 7
        push(val)
        """
        sp = self.get(SP_REG, PTR_TYPE)
        val = self.constant(0, STACK_ENTRY_TYPE)
        for i in range(7, -1, -1):
            x = self.load(sp -i + i, STACK_ENTRY_TYPE)
            val = val << 1 | (x & 1)
        self.store(val, sp - 8)
        self.put(sp - 7, SP_REG)

class Instruction_NOP(VMWHEREInstruction):

    bin_format = 'x' * 8
    name = 'nop'

    def compute_result(self, *args):
        """
        match anything
        should not get here
        """
        pass


# The instrs are in this order so we try NOP last.
all_instrs = [
    Instruction_EXIT,    # 00
    Instruction_ADD,     # 01
    Instruction_SUB,     # 02
    Instruction_AND,     # 03
    Instruction_OR,      # 04
    Instruction_XOR,     # 05
    Instruction_SHL,     # 06
    Instruction_SHR,     # 07
    Instruction_READ,    # 08
    Instruction_WRITE,   # 09
    Instruction_PUSH,    # 0a
    Instruction_JLZ,     # 0b
    Instruction_JZ,      # 0c
    Instruction_JMP,     # 0d
    Instruction_POP,     # 0e
    Instruction_PUSHSTK, # 0f
    Instruction_REV,     # 10
    Instruction_EXP,     # 11
    Instruction_SQZ,     # 12
    Instruction_NOP,     # xx
]

class LifterVMWHERE(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterVMWHERE, 'vmwhere')
