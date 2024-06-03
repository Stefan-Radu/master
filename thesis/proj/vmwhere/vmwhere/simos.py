from angr.simos import SimUserland, register_simos
from angr.simos.userland import SimUserland
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary
from angr import SimProcedure
from angr.calling_conventions import SimCCSyscall, register_syscall_cc, register_default_cc, SimCCUnknown, SimRegArg
from .arch import ArchVMWHERE

class WriteByte(SimProcedure):
    """
    corresponds with opcode 0x9
    """
    def run(self, sp):
        # pylint:disable=unused-argument
        print('write syscall')
        self.state.posix.fd[1].write(sp, 1)


class ReadByte(SimProcedure):
    """
    corresponds with opcode 0xa
    """
    def run(self, sp):
        print('read syscall')
        self.state.posix.fd[0].read(sp - 1, 1)


P['vmwhere'] = {}
P['vmwhere']['write_byte'] = WriteByte
P['vmwhere']['read_byte'] = ReadByte

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('vmwhere')
syscall_lib.add_all_from_dict(P['vmwhere'])
syscall_lib.add_number_mapping_from_dict('vmwhere', {0 : 'read_byte',
                                                     1 : 'write_byte'})

# TODO from where
class SimVMWHERE(SimUserland):
    """
    Defines the "OS" of a BrainFuck program.

    This means:
    -  The memory layout (separate code and data)
    -  The "syscalls" (read stdin and write stdout)

    """

    def __init__(self, project, **kwargs):
        super(SimVMWHERE, self).__init__(
            project,
            syscall_library=L['vmwhere'],
            syscall_addr_alignment=8,
            name='vmwhere',
            **kwargs)

    def state_blank(self, stack_size=0x1000, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimVMWHERE, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # SP halfway through memory
        state.regs.sp = 0x80000000
        state.regs.bp = state.regs.sp
        state.memory.map_region(state.regs.sp, stack_size, 3, init_zero=True)
        return state

    def state_entry(self, **kwargs):
        state = super(SimVMWHERE, self).state_entry(**kwargs)
        return state


class SimCCVMWHERESyscall(SimCCSyscall):
    ARG_REGS = [ 'sp' ]
    FP_ARG_REGS = []
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = ArchVMWHERE

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.sysnum


register_simos('vmwhere', SimVMWHERE)
register_syscall_cc('vmwhere','vmwhere', SimCCVMWHERESyscall)
# register_syscall_cc('vmwhere','default', SimCCVMWHERESyscall)
register_default_cc('vmwhere',SimCCUnknown)
