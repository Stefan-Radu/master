from archinfo.arch import Arch, Register, register_arch
from archinfo.types import Endness, RegisterOffset
from archinfo import ArchAArch64


class ArchVMWHERE(Arch):

    memory_endness = Endness.LE
    bits = 64
    vex_arch = None
    name = "vmwhere"
    instruction_alignment = 1
    stack_size = 0x1000
    stack_change = 8

    # registers is a dictionary mapping register names, to a tuple of
    # register offset, and their width, in bytes

    register_list = [
        Register(name="ip", size=8, vex_offset=0),
        Register(name="bp", size=8, vex_offset=8),
        Register(name="sp", size=8, vex_offset=16),
        Register(name="sysnum", size=8, vex_offset=24),
        Register(name="ip_at_syscall", size=8, vex_offset=32),
    ]
    ip_offset = RegisterOffset(0)
    sp_offset = RegisterOffset(2)

    def __init__(self, endness=Endness.LE):
        self.cs_mode = None
        # forces LITTLE endian
        super().__init__(Endness.LE)


register_arch(['vmwhere|VMWHERE'], 64, Endness.LE, ArchVMWHERE)
