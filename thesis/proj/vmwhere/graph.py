from vmwhere import ArchVMWHERE, LifterVMWHERE
from vmwhere.lifter import Instruction_JLZ, Instruction_JMP, Instruction_JZ
from pyvex.lifting.util import *


def get_jump_dst(instr):
    jump_offset = int(instr.data['x'], 2)
    dst = (instr.addr + 3 + jump_offset) % 0x10000
    if dst & (0x8000):
        dst = dst - 0xffff - 1
    return dst

def disassemble(insts):
    disassembly = []
    for addr, name, args, desc in insts:
        args_str = ", ".join(str(a) for a in args)
        dis_str = f"{addr:#06x}:  {name} {args_str}"
        if desc:
            dis_str += f"| {desc}"
        disassembly.append(dis_str)
    return r"\l".join(disassembly) + r'\l'


arch = ArchVMWHERE()
lift = LifterVMWHERE(arch, 0)

with open("./program", "rb") as f:
    lift.data = f.read()[3:]
    lift.lift(lift.data, disasm=True)

instructions = lift.decode()

edges = {}
block_ends = []

# block separation; adding edges
for instr in instructions:
    if type(instr) in [Instruction_JZ, Instruction_JLZ, Instruction_JMP]:
        dst = get_jump_dst(instr)
        cont = instr.addr + 3
        block_ends.append(cont - 1)
        block_ends.append(dst - 1)
        if not instr.addr in edges:
            edges[instr.addr] = []
        if type(instr) in [Instruction_JLZ, Instruction_JZ]:
            edges[instr.addr].append((dst, 'green'))
            edges[instr.addr].append((cont, 'red'))
        else:
            edges[instr.addr].append((dst, 'orange'))
            # edges.append((dst - 1, dst, 'black'))


f = open("cfg.dot", "w")
f.write("digraph CFG_VMWHERE {\n")

start = 0
block_of = {}
disass = lift.disassemble()
block_ends = sorted(list(set(block_ends)))

def get_block(start, end):
    dis = []
    for line in disass:
        if line[0] < start:
            continue
        if line[0] > end:
            break
        dis.append(line)
    return dis

# block extraction; adding nodes to the graph
for i, end in enumerate(block_ends):
    block = get_block(start, end)
    dis = disassemble(block)
    f.write(f"node_{start} [\nlabel=\"{dis}\"\nshape=box\n"\
            "fillcolor=lightgray];\n")
    for j in range(start, end + 1):
        block_of[j] = start
    start = end + 1

# normalise edges
normalised_edges = {}
for start, li in edges.items():
    start_block = block_of[start]
    normalised_edges[start_block] = []
    for end, color in li:
        end_block = end
        if end in block_of:
            end_block = block_of[end]
        normalised_edges[start_block].append((end_block, color))

# add missing edges
for end in block_ends:
    if block_of[end] not in normalised_edges:
        normalised_edges[block_of[end]] = [(block_of[end + 1], 'gray')]

# adding edges to the file
for start, li in normalised_edges.items():
    for end, color in li:
        if end not in block_of:
            f.write(f"node_{block_of[start]} -> node_{end} "\
                    f"[color={color}, penwidth=2.0];\n")
        else:
            f.write(f"node_{block_of[start]} -> node_{block_of[end]} "\
                    f"[color={color}, penwidth=2.0];\n")

f.write("}")
f.close()
