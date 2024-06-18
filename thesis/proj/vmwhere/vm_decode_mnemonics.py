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


# Transform native assembly into IR
def get_block(lifter, ircfg, mdis, addr):
    loc_key = ircfg.get_or_create_loc_key(addr)
    if loc_key not in ircfg.blocks:
        block = mdis.dis_block(int(addr))
        # print(block)
        lifter.add_asmblock_to_ircfg(block, ircfg)
    block = ircfg.get_block(loc_key)

    if block is None:
        raise LookupError('No block found at that address: %s' % loc_key)
    return block

loc_db = LocationDB()
cont = Container.from_stream(open('./chal', 'rb'), loc_db)

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

infos = {}

vm_sp_init = ExprId('VM_SP', 64)
vm_sp_addr = expr_simp(ExprMem(regs.RBP + ExprInt(0xFFFFFFFFFFFFFFF0, 64), 64))
infos[vm_sp_addr] = vm_sp_init

vm_ip_init = ExprId('VM_IP', 64)
vm_ip_addr = expr_simp(ExprMem(regs.RBP + ExprInt(0xFFFFFFFFFFFFFFE8, 64), 64))
infos[vm_ip_addr] = vm_ip_init

# for i in range(8):
    # vm_sp_offset = ExprId(f'VM_SP_OFFSET_{i - 1}', 8)
    # vm_sp_off_addr = expr_simp(ExprMem(vm_sp_addr + ExprInt(i - 1, 64), 8))
    # infos[vm_sp_off_addr] = vm_sp_offset

stack_top = ExprId('STACK_TOP', 8)
stack_top_val = expr_simp(ExprMem(vm_sp_init + ExprInt(0xFFFFFFFFFFFFFFFF, 64), 8))
infos[stack_top_val] = stack_top
print(stack_top_val)

addition_infos = dict(infos.copy())

j = ExprId('J', 32)
j_addr = expr_simp(ExprMem(regs.RBP + ExprInt(0xFFFFFFFFFFFFFFE0, 64), 32))
addition_infos[j_addr] = j



def dump_state(sb, addr):
    print('====================================')
    out = {}
    for expr, value in sorted(sb.symbols.items()):
        if (expr, value) in initial_symbols:
            continue
        if (expr, value) in addition_infos:
        # if expr in addition_infos:
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    sb.lifter.IRDst, regs.RIP, regs.RAX, regs.RCX, regs.RDX, regs.RSI,
                    regs.RAX, regs.RDI]:
            continue

        expr = expr_simp(expr.replace_expr(infos))
        value = expr_simp(value.replace_expr(infos))
        if expr == value:
            continue
        out[expr] = value


    print(f'{'-' * 20} {addr} {'-' * 20}\n')
    out = sorted(out.items())
    x86_regs = []
    mem = []
    other = []
    for expr, value in out:
        if expr in regs.all_regs_ids:
            x86_regs.append((expr, value))
        elif isinstance(expr, ExprMem):
            mem.append((expr, value))
        else:
            other.append((expr, value))

    print( "Regs:")
    for item in other:
        print( "\t%s = %s" % item)
    print("Mem:")
    for item in mem:
        print("\t%s = %s" % item)
    print("x86:")
    for item in x86_regs:
        print("\t%s = %s" % item)
    # for item in out:
        # print("  %s = %s" % item)
    # print("Mem:")
    # for item in mem:
        # print("\t%s = %s" % item)
    #print "x86:"
    #for item in x86_regs:
    #    print "\t%s = %s" % item
    print()


MNEMONIC_ADDR = 0x17de
# MNEMONIC_ADDR = 0x1694
END_ADDR = 0x18cf
addr = ExprInt(MNEMONIC_ADDR, 64)
end_addr = ExprInt(END_ADDR, 64)
print(addr)

sb = SymbolicExecutionEngine(lifter)
for k, v in infos.items():
    sb.symbols[k] = v

print(f'{'*' * 15} | Mnemonic {0x10} | addr: {addr} | {'*' * 15}\n')

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
    # sb.del_mem_above_stack(sb.lifter.sp)

    if addr == end_addr:
        print("Ret addr reached")
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
