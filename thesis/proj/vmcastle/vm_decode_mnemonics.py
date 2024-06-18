from argparse import ArgumentParser
from pdb import pm
from pprint import pp

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
# from miasm.arch.x86.arch import mn_x86
from miasm.arch.x86 import regs
from miasm.core.utils import *
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine

import IPython


BASE_ADDR = 0x100000

# Transform native assembly into IR
def get_block(lifter, ircfg, mdis, addr):
    loc_key = ircfg.get_or_create_loc_key(addr)
    if loc_key not in ircfg.blocks:
        block = mdis.dis_block(int(addr))
        lifter.add_asmblock_to_ircfg(block, ircfg)
    block = ircfg.get_block(loc_key)

    if block is None:
        raise LookupError('No block found at that address: %s' % loc_key)
    return block

MNEMONIC_ARRAY_ADDR = 0x00105020
MNEMONIC_CNT = 117


loc_db = LocationDB()
cont = Container.from_stream(open('./vm', 'rb'), loc_db, addr=BASE_ADDR)

arch = cont.arch
machine = Machine(arch)
lifter = machine.lifter(loc_db)
ircfg = lifter.new_ircfg()
bs = cont.bin_stream
mdis = machine.dis_engine(bs, loc_db=loc_db)

# IPython.embed()

# cont.s
# mdis = machine.dis_engine(bs, symbol_pool=cont.symbol_pool)
# ir_arch = ir_x86_32(mdis.symbol_pool)


symbols_init = dict(regs.regs_init)
initial_symbols = symbols_init.items()

ret_addr = ExprId('RET_ADDR', 64)
vm_ip_init = ExprId('VM_IP_INIT', 32)
vm_sp_init = ExprId('VM_SP_INIT', 32)
vm_regs = ExprId('VM_REGS', 32 * 4)
vm_r1_init = ExprId('VM_R1_INIT', 32)
vm_r2_init = ExprId('VM_R2_INIT', 32)
vm_r3_init = ExprId('VM_R3_INIT', 32)
vm_ac_init = ExprId('VM_AC_INIT', 32)
byte_arg = ExprId('ARG', 64)
vm_stack = ExprId('STACK', 32 * 1024)

putchr = ExprId('putchr', 64)
getchr = ExprId('getchr', 64)


infos = {}
# infos[expr_simp(ExprMem(regs.ECX_init, 32))] = vm_pc_init

# Push return addr
infos[expr_simp(ExprMem(regs.RSP_init - ExprInt(8, 64), 64))] = ret_addr
infos[regs.RSP] = expr_simp(regs.RSP_init - ExprInt(8, 64))

# set argunent
infos[regs.RDI] = byte_arg

# infos[expr_simp(ExprMem(ExprInt(0x6840, 64), 32 * 4))] = vm_regs
infos[expr_simp(ExprMem(ExprInt(0x6840, 64), 32))] = vm_ip_init
infos[expr_simp(ExprMem(ExprInt(0x6844, 64), 32))] = vm_sp_init
infos[expr_simp(ExprMem(ExprInt(0x6850, 64), 32))] = vm_r1_init
infos[expr_simp(ExprMem(ExprInt(0x6854, 64), 32))] = vm_r2_init
infos[expr_simp(ExprMem(ExprInt(0x6858, 64), 32))] = vm_r3_init
infos[expr_simp(ExprMem(ExprInt(0x685c, 64), 32))] = vm_ac_init
infos[expr_simp(ExprMem(ExprInt(0x5840, 64), 32 * 1024))] = vm_stack
infos[expr_simp(ExprMem(ExprInt(0x4f88, 64), 64))] = putchr
infos[expr_simp(ExprMem(ExprInt(0x4fb8, 64), 64))] = getchr

# for i in range(0, 5):
    # infos[expr_simp(ExprMem(regs.ECX_init + ExprInt((i + 1) * 4, 32), 32))] \
        # = ExprId(f"REG{i}", 32)

# pp(expr_simp(ExprMem(regs.ECX_init + ExprInt((42) * 4, 32), 32)))
# pp(expr_simp_explicit(ExprMem(regs.ECX_init + ExprInt((42) * 4, 32), 32)))
# pp(ExprMem(regs.ECX_init + ExprInt((42) * 4, 32), 32))

addition_infos = dict(infos)

# empty menmonics
for i in range(118, 256):
    e = expr_simp(ExprMem(ExprInt(MNEMONIC_ARRAY_ADDR - BASE_ADDR + i * 8, 32), 32))
    addition_infos[e] = ExprInt(0, 32)

# # imm
# expr_imm8 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 8))
# addition_infos[expr_imm8] = ExprId("imm8" , 8)

# expr_imm16 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 16))
# addition_infos[expr_imm16] = ExprId("imm16" , 16)

# expr_imm32 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 32))
# addition_infos[expr_imm32] = ExprId("imm32" , 32)

# # immb
# expr_imm8b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 8))
# addition_infos[expr_imm8b] = ExprId("imm8b" , 8)

# expr_imm16b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 16))
# addition_infos[expr_imm16b] = ExprId("imm16b" , 16)

# expr_imm32b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 32))
# addition_infos[expr_imm32b] = ExprId("imm32b" , 32)

# imms = set([expr_imm8, expr_imm16, expr_imm32,
            # expr_imm8b, expr_imm16b, expr_imm32b])

# imm8 = ExprId('imm8', 8)
#imm8 = ExprId('imm8XXX', 8)
#imm8 = expr_imm8
# (ECX_init+(({@8[(VM_PC_init+0x1)],0,8, 0x0,8,32}&0xF)*0x4)+0xC)

# base_regx = expr_simp(regs.ECX_init
                      # + (imm8.zeroExtend(32) & ExprInt(0xf, 32))
                      # * ExprInt(4, 32)
                      # + ExprInt(0xf, 32))

# addition_infos[expr_simp(ExprMem(base_regx, 32))] = ExprId("REGX", 32)[:32]
# addition_infos[expr_simp(ExprMem(base_regx, 16))] = ExprId("REGX", 32)[:16]
# addition_infos[expr_simp(ExprMem(base_regx,  8))] = ExprId("REGX", 32)[: 8]

# base_regy = expr_simp(regs.ECX_init
                      # + (imm8[4:8].zeroExtend(32))
                      # * ExprInt(4, 32)
                      # + ExprInt(0xC, 32))

# addition_infos[expr_simp(ExprMem(base_regy, 32))] = ExprId("REGY", 32)[:32]
# addition_infos[expr_simp(ExprMem(base_regy, 16))] = ExprId("REGY", 16)[:16]
# addition_infos[expr_simp(ExprMem(base_regy,  8))] = ExprId("REGY",  8)[:8]

def dump_state(sb, addr):
    out = {}
    for expr, value in sorted(sb.symbols.items()):
        if (expr, value) in initial_symbols:
            continue
        if (expr, value) in addition_infos:
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    sb.lifter.IRDst, regs.RIP, regs.RAX, regs.RCX, regs.RDX, regs.RSI,
                    regs.RAX, regs.RDI]:
            continue
        expr_s = expr_simp(expr.replace_expr(infos))
        expr = expr_s
        value = expr_simp(value.replace_expr(infos))
        if expr == value:
            continue
        out[expr] = value

    print(f'{'-' * 20} {addr} {'-' * 20}\n')
    out = sorted(out.items())
    for item in out:
        print("  %s = %s" % item)
    # print("Mem:")
    # for item in mem:
        # print("\t%s = %s" % item)
    #print "x86:"
    #for item in x86_regs:
    #    print "\t%s = %s" % item
    print()



mnemonic_addresses = set()

for i in range(MNEMONIC_CNT):
# for i in range(103):
    bytes_read = bs.getbytes(MNEMONIC_ARRAY_ADDR - BASE_ADDR + i * 8, 8)
    addr = ExprInt(upck64(bytes_read), 32)

    if addr in mnemonic_addresses:
        continue
    mnemonic_addresses.add(addr)

    sb = SymbolicExecutionEngine(lifter)
    for k, v in infos.items():
        sb.symbols[k] = v

    print(f'{'*' * 15} | Mnemonic {i} | addr: {addr} | {'*' * 15}\n')

    symbols = frozenset(sb.symbols.items())
    todo = set([(addr, symbols)])

    count = 20
    while todo and count > 0:
        count -=1
        addr, symbols = todo.pop()

        if not get_block(lifter, ircfg, mdis, addr):
            raise ValueError("Unknown destination %s" % addr)

        sb.symbols.symbols_id.clear()
        sb.symbols.symbols_mem.clear()
        for k, v in symbols:
            sb.symbols[k] = v

        start_addr = addr
        addr = sb.run_block_at(ircfg, addr)
        sb.del_mem_above_stack(sb.lifter.sp)

        if addr is ret_addr:
            # print("Ret addr reached")
            ret_mn = expr_simp(sb.eval_expr(regs.EAX[:8]))
            dump_state(sb, start_addr)
            continue

        if isinstance(addr, ExprCond):
            todo.add((addr.src1, frozenset(sb.symbols.items())))
            todo.add((addr.src2, frozenset(sb.symbols.items())))
            continue
        if not (addr.is_loc() or addr.is_int()):
            print("BAD END", addr)
            break
        todo.add((addr, frozenset(sb.symbols.items())))

    if count == 0:
        print('Mnemonic too complex')
