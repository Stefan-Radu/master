from vmwhere.lifter import LifterVMWHERE
from vmwhere.arch import ArchVMWHERE
import IPython


lifter = LifterVMWHERE(ArchVMWHERE(), 0)

# with open('./program', 'rb') as f:
with open('./test', 'rb') as f:
    lifter.data = f.read()[3:]
    # lifter.data = f.read()

disasstr = ""
insts = lifter.disassemble()
for addr, name, args in insts:
    args_str = ", ".join(str(a) for a in args)
    disasstr += f"{addr:#06x}:  {name} {args_str}\n"
print(disasstr)
