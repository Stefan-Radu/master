from archinfo.arch import Arch, Register
from archinfo.types import Endness
from archinfo import register_arch

class Arch_TC_UMD_24(Arch):

    memory_endness = Endness.BE
    bits = 16
    vex_arch = None
    name = "TC_UMD_24"

    register_list = [
        Register(name="ip", size=2, vex_offset=0),
        Register(name="sp", size=2, vex_offset=2),
    ]


    def __init__(self, endness=Endness.BE):
        super().__init__(Endness.BE)
        ip_offset = self.registers["ip"][0]

register_arch(['tc_umd_24'], 16, Endness.ANY, Arch_TC_UMD_24)
