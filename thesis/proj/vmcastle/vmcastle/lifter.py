import bitstring
from pyvex.lifting.util import *
from pyvex.lifting import register
from pyvex.lifting.util.syntax_wrapper import VexValue

import logging

log = logging.getLogger("vmcastle.lifter")



# This file is autogenerated with the `arch-genesys` tool
# project name: vmcastle
# date: 2024-06-08T11:40:55.210350+00:00


# refferenced types
PTR_TYPE = Type.int_32
STACK_ENTRY_TYPE = Type.int_32


# refferenced registers
IP_REG = 'ip'
SP_REG = 'sp'
SYSNUM_REG = 'sysnum'
IP_AT_SYSCALL_REG = 'ip_at_syscall'
R1_REG = 'r1'
R2_REG = 'r2'
R3_REG = 'r3'
AC_REG = 'ac'
REG_NO_REG = 'reg_no'

STACK_BASE = 0x10005840


# utils
def get_reg(r):
    return {
        0: R1_REG,
        1: R2_REG,
        2: R3_REG,
        3: AC_REG,
    }[r & 3]

def change_sp(sp, val):
    sp = sp - STACK_BASE + val * 4
    sp = sp % 0x400
    sp = sp + STACK_BASE
    return sp

# def signed(self):
    # r = int(self.data['r'], 2)
    # if r >= 128:
        # r = -(0xff - r - 1)
    # return r


# disassembly functions
def disassemble_generic(self):
    arg = self.rawbits[2:]
    if arg:
        arg = int(self.rawbits[2:], 16)
        arg = hex(arg)
    return self.addr, self.name, [], self.description

def disassemble_push(self):
    r = int(self.data['r'], 2).to_bytes(1)
    return self.addr, self.name, [r], self.description

def disassemble_jmp(self):
    arg = int(self.rawbits[2:], 16)
    if arg & (0x8000):
        offset = arg - 0xffff - 1
    else:
        offset = arg
    jmp = self.addr + 3 + offset
    return self.addr, self.name, [hex(jmp), jmp, offset], self.description

def disassemble_reg(self):
    r = int(self.data['r'], 2)
    reg = get_reg(r)
    return self.addr, self.name, [reg], self.description

def disassemble_bit(self):
    r = int(self.data['r'], 2)
    return self.addr, self.name, [r & 1], self.description


###################################################
# architecture instructions implementation in VEX #
###################################################

class Instruction_NOP(Instruction):
    bin_format = 'xxxxxxxxxxxxxxxx'
    name = 'nop'
    description = 'nop. just nothing'

    def compute_result(self, *args):
        pass
        # if self.addr < 0x100000:
            # log.error(f"nop found: {hex(self.addr)}")

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_EXIT(Instruction):
    bin_format = '01110101xxxxxxxx'
    name = 'exit'
    description = 'exit program'

    def compute_result(self, *args):
        self.jump(None, self.constant(self.addr, PTR_TYPE), jumpkind=JumpKind.Exit)

    def disassemble(self):
        return disassemble_generic(self)

    def parse(self,bitstream):
        self.last_instruction = False
        data = Instruction.parse(self, bitstream)
        try:
            bitstream.peek(16)
        except bitstring.ReadError:
            # We ran off the end!
            self.last_instruction = True
        return data 

class Instruction_POP_REG(Instruction):
    bin_format = '01100110rrrrrrrr'
    name = 'pop_reg'
    description = ''

    def compute_result(self, *args):
        r = int(self.data['r'], 2)
        reg = get_reg(r)
        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp, STACK_ENTRY_TYPE)
        self.put(top, reg)

        sp = change_sp(sp, -1)
        self.put(sp, SP_REG)

    def disassemble(self):
        return disassemble_reg(self)


class Instruction_PUSH_REG(Instruction):
    bin_format = '01100111rrrrrrrr'
    name = 'push_reg'
    description = 'push the value in the register on the stack'

    def compute_result(self, *args):
        r = int(self.data['r'], 2)
        reg = get_reg(r)
        val = self.get(reg, PTR_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)
        sp = change_sp(sp, 1)
        self.store(val, sp)
        self.put(sp, SP_REG)

    def disassemble(self):
        return disassemble_reg(self)


class Instruction_PUSH_IMM(Instruction):
    bin_format = '01101000rrrrrrrr'
    name = 'push_imm'
    description = ''

    def compute_result(self, *args):
        # val = signed(self)
        val = self.constant(int(self.data['r'], 2), Type.int_8).signed
        val = val.cast_to(PTR_TYPE, signed=True)
        sp = self.get(SP_REG, PTR_TYPE)
        sp = change_sp(sp, 1)
        # self.store(self.constant(val, PTR_TYPE), sp)
        self.store(val, sp)
        self.put(sp, SP_REG)

    def disassemble(self):
        return disassemble_push(self)


class Instruction_ADD(Instruction):
    bin_format = '01101001rrrrrrrr'
    name = 'add'
    description = 'ac = r1 + r2'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE)
        r2 = self.get(R2_REG, PTR_TYPE)
        self.put(r1 + r2, AC_REG)

    def disassemble(self):
        return disassemble_generic(self)


class Instruction_SUB(Instruction):
    bin_format = '01101010rrrrrrrr'
    name = 'sub'
    description = 'ac = r1 - r2'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE)
        r2 = self.get(R2_REG, PTR_TYPE)
        self.put(r1 - r2, AC_REG)
        

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_MUL(Instruction):
    bin_format = '01101011rrrrrrrr'
    name = 'mul'
    description = 'ac = r1 * r2'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE)
        r2 = self.get(R2_REG, PTR_TYPE)
        self.put(r1 * r2, AC_REG)

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_DIV(Instruction):
    bin_format = '01101100rrrrrrrr'
    name = 'div'
    description = 'ac = r1 / r2'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE)
        r2 = self.get(R2_REG, PTR_TYPE)
        self.put(r1 / r2, AC_REG)

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_MOD(Instruction):
    bin_format = '01101101rrrrrrrr'
    name = 'mod'
    description = 'ac = r1 % r2'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE)
        r2 = self.get(R2_REG, PTR_TYPE)
        self.put(r1 % r2, AC_REG)

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_JMP_REG(Instruction):
    bin_format = '01101110rrrrrrrr'
    name = 'jmp_reg'
    description = ''

    def compute_result(self, *args):
        r = int(self.data['r'], 2)
        reg = get_reg(r)
        offset = self.get(reg, PTR_TYPE).signed * 2
        offset = offset.cast_to(PTR_TYPE, signed=True)
        dst = self.constant(self.addr + 2, PTR_TYPE) + offset
        self.jump(None, dst)


    def disassemble(self):
        return disassemble_reg(self)


class Instruction_JMP_COND(Instruction):
    bin_format = '01101111rrrrrrrr'
    name = 'jmp_cond'
    description = 'jump with reg offset, based on AC | AC < 0: +R1 | AC == 0: +R2 | AC > 0: +R3'

    def compute_result(self, *args):
        ac = self.get(AC_REG, PTR_TYPE).signed
        dst_r1 = self.get(R1_REG, PTR_TYPE).signed
        dst_r2 = self.get(R2_REG, PTR_TYPE).signed
        dst_r3 = self.get(R3_REG, PTR_TYPE).signed

        dst = dst_r1
        dst = self.ite(ac == 0, dst_r2, dst)
        dst = VexValue(self.irsb_c, dst)

        dst = self.ite(ac > 0, dst_r3, dst)
        dst = VexValue(self.irsb_c, dst)

        dst = dst * self.constant(2, PTR_TYPE) + self.addr + 2
        self.jump(None, dst)


    def disassemble(self):
        return disassemble_generic(self)


class Instruction_CMP(Instruction):
    bin_format = '01110000rrrrrrrr'
    name = 'cmp'
    description = 'compare R1 and R2; set AC'

    def compute_result(self, *args):
        r1 = self.get(R1_REG, PTR_TYPE).signed
        r2 = self.get(R2_REG, PTR_TYPE).signed
        # import IPython
        # IPython.embed()
        cmp1 = self.ite(r1 < r2,
                       self.constant(1, PTR_TYPE),
                       self.constant(0, PTR_TYPE))
        cmp1 = VexValue(self.irsb_c, cmp1)
        # cmp2 = self.ite(r1 == r2,
                       # self.constant(1, PTR_TYPE),
                       # self.constant(0, PTR_TYPE))
        # cmp2 = VexValue(self.irsb_c, cmp2)
        cmp3 = self.ite(r1 > r2,
                       self.constant(1, PTR_TYPE),
                       self.constant(0, PTR_TYPE))
        cmp3 = VexValue(self.irsb_c, cmp3)

        val = cmp1 * 1 + cmp3 * -1
        self.put(val, AC_REG)

    def disassemble(self):
        return disassemble_generic(self)

    
class Instruction_PRINT_REG(Instruction):
    bin_format = '01110001rrrrrrrr'
    name = 'print_reg'
    description = ''

    def compute_result(self, *args):
        r = int(self.data['r'], 2) & 3
        self.put(self.constant(1, PTR_TYPE), SYSNUM_REG)
        self.put(self.constant(r, PTR_TYPE), REG_NO_REG)
        dst = self.constant(self.addr + 2, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)

    def disassemble(self):
        return disassemble_reg(self)

    
class Instruction_READ_REG(Instruction):
    bin_format = '01110010rrrrrrrr'
    name = 'read_reg'
    description = ''

    def compute_result(self, *args):
        r = int(self.data['r'], 2) & 3
        self.put(self.constant(0, PTR_TYPE), SYSNUM_REG)
        self.put(self.constant(r, PTR_TYPE), REG_NO_REG)
        dst = self.constant(self.addr + 2, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


    def disassemble(self):
        return disassemble_reg(self)


class Instruction_STACK_TOP_ITSHL(Instruction):
    bin_format = '01110011rrrrrrrr'
    name = 'stack_top_itshl'
    description = 'shift top of stack to the left with 1 if param is not 0'

    def compute_result(self, *args):
        r = int(self.data['r'], 2) & 1
        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp, PTR_TYPE)
        val = top * (self.constant(r, PTR_TYPE) + 1)
        self.store(val, sp)


    def disassemble(self):
        return disassemble_bit(self)

    
class Instruction_STACK_TOP_ITADD(Instruction):
    bin_format = '01110100rrrrrrrr'
    name = 'stack_top_itadd'
    description = 'add 1 to the top of the stack if the param is not 0'

    def compute_result(self, *args):
        r = int(self.data['r'], 2) & 1
        sp = self.get(SP_REG, PTR_TYPE)
        top = self.load(sp, PTR_TYPE)
        val = top + self.constant(r, PTR_TYPE)
        self.store(val, sp)


    def disassemble(self):
        return disassemble_bit(self)


# The instrs are matched against in this exact order
all_instrs = [
    Instruction_EXIT,    # 2
    Instruction_POP_REG,    # 3
    Instruction_PUSH_REG,    # 4
    Instruction_PUSH_IMM,    # 5
    Instruction_ADD,    # 6
    Instruction_SUB,    # 7
    Instruction_MUL,    # 8
    Instruction_DIV,    # 9
    Instruction_MOD,    # 10
    Instruction_JMP_REG,    # 11
    Instruction_JMP_COND,    # 12
    Instruction_CMP,    # 13
    Instruction_PRINT_REG,    # 14
    Instruction_READ_REG,    # 15
    Instruction_STACK_TOP_ITSHL,    # 16
    Instruction_STACK_TOP_ITADD,    # 17
    Instruction_NOP,    # 1
    ]

class LifterVMCASTLE(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterVMCASTLE, 'vmcastle')


# a simple disassembly function using the lifter
def disassemble(file_path, arch):
    lifter = LifterVMCASTLE(arch, 0)

    with open(file_path, 'rb') as f:
        lifter.data = f.read()[0:]

    disassembly = []
    insts = lifter.disassemble()
    for addr, name, args, desc in insts:
        args_str = ", ".join(str(a) for a in args)
        dis_str = f"{addr:#06x}:  {name} {args_str}"
        if desc:
            dis_str += f" | {desc}"
        disassembly.append(dis_str)

    return "\n".join(disassembly)
