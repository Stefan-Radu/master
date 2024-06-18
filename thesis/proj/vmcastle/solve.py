from vmcastle import *
import angr
import claripy

START = 0x17e8
LOSE = 0xa1dc
SYSCALL = 0x100000
WIN = 0xa1a4

p = angr.Project("program")
entry_state = p.factory.entry_state(addr=START)
sm = p.factory.simgr(entry_state)

flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(85)]
flag = claripy.Concat(*flag_chars)
for c in flag_chars:
    sp = sm.one_active.regs.sp
    sm.one_active.regs.sp += 4
    sm.one_active.mem[sp].byte.store(c)
sm.one_active.regs.sp -= 4

for c in flag_chars:
    sm.one_active.solver.add(c >= 0x20)
    sm.one_active.solver.add(c <= 0x80)

sm.one_active.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
sm.explore(avoid = lambda s: LOSE <= s.addr < SYSCALL, find=WIN)

sol = sm.one_found.solver.eval(flag, cast_to=bytes)
print(sol)
