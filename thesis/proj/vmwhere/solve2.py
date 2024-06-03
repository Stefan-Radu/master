from vmwhere import *
import angr
import claripy

import IPython
import os
import signal

import string

##########################################################################

def killmyself():
    os.system('kill %d' % os.getpid())

def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
    IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

##########################################################################

def get_input_byte_constraints():
    li = []
    with open("./program", "rb") as f:
        data = f.read()[3:]
        for i in range(2419, len(data), 12):
            if data[i - 1] != 0xa:
                break
            li.append(data[i])
    return li[::-1]

p = angr.Project("./program")

flag_char = claripy.BVS(f'flag_char', 8)
start_state = p.factory.entry_state(addr=116, stdin=flag_char)

alphabet = string.ascii_lowercase + string.digits + string.punctuation
terms = [flag_char == cc for cc in alphabet]
start_state.solver.add(claripy.Or(*terms))
constraints = get_input_byte_constraints()

sm = p.factory.simgr(start_state)
sm.explore(find=118)
sm.move('found', 'active')
sm.explore(find=168, num_find=1000)

IPython.embed()

flag_bytes = []
for constr in constraints:
    for s in sm.found:
        sp = s.regs.sp
        if s.mem[sp - 1].byte.concrete == constr:
            flag_bytes.append(s.posix.dumps(0))

flag = b''.join(flag_bytes)
print(flag)
