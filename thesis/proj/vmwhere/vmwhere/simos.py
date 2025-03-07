from angr.simos import SimUserland, register_simos
from angr.simos.userland import SimUserland
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary
from angr import SimProcedure
from angr.calling_conventions import SimCCSyscall, register_syscall_cc, register_default_cc, SimCCUnknown, SimRegArg
from .arch import ArchVMWHERE



class ReadByte(SimProcedure):
    # Reads a byte from stdin
    def run(self,sp): 
        self.state.posix.fd[0].read(sp - 1, 1) 

class WriteByte(SimProcedure):
    # Write a byte to stdout
    def run(self,sp): 
        self.state.posix.fd[1].write(sp, 1) 


P['vmwhere'] = {}
P['vmwhere']['readbyte'] = ReadByte
P['vmwhere']['writebyte'] = WriteByte


syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('vmwhere')
syscall_lib.add_all_from_dict(P['vmwhere'])
syscall_lib.add_number_mapping_from_dict('vmwhere', {
    0 : 'readbyte',
    1 : 'writebyte',
    })


class SimVMWHERE(SimUserland):
    """
    Defines the "OS" of a vmwhere program.

    This means:
    -  The memory layout (separate code and data)
    -  The "syscalls" (read stdin and write stdout)
    -  The calling convention (params, return, etc.)
    """

    def __init__(self, project, **kwargs):
        super(SimVMWHERE, self).__init__(
            project,
            syscall_library=L['vmwhere'],
            syscall_addr_alignment=8,
            name='vmwhere',
            **kwargs)

    def state_blank(self, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimVMWHERE, self).state_blank(
            stack_size=4096,
            stack_end=2147483648,
            **kwargs)  # pylint:disable=invalid-name

        # Init other registers besides SP
        state.regs.bp = 2147483648

        # allocate stack space if the stack doesn't "grow down"
        state.memory.map_region(state.regs.sp, 4096, 3, init_zero=True)
        
        return state

    def state_entry(self, **kwargs):
        state = super(SimVMWHERE, self).state_entry(**kwargs)
        return state


class SimCCVMWHERESyscall(SimCCSyscall):
    ARG_REGS = ['sp']
    
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
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