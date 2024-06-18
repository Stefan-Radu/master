from angr.simos import SimUserland, register_simos
from angr.simos.userland import SimUserland
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary
from angr import SimProcedure
from angr.calling_conventions import SimCCSyscall, register_syscall_cc, register_default_cc, SimCCUnknown, SimRegArg
from .arch import ArchVMCASTLE


def set_reg(state, r, val):
    assert(r.concrete)
    r = r.concrete_value
    if r == 0:
        state.regs.r1 = val
    if r == 1:
        state.regs.r2 = val
    if r == 2:
        state.regs.r3 = val
    if r == 3:
        state.regs.ac = val

def set_reg2(state, r, val):
    assert(r.concrete)
    r = r.concrete_value
    state.registers.store(20 + r * 4, val, 1)

def get_reg(state, r):
    assert(r.concrete)
    r = r.concrete_value
    if r == 0:
        return state.regs.r1
    if r == 1:
        return state.regs.r2
    if r == 2:
        return state.regs.r3
    if r == 3:
        return state.regs.ac

class ReadByte(SimProcedure):
    # Reads a byte from stdin into the specified register
    def run(self, reg_no):
        tmp = self.state.posix.fd[0].read_data(1)[0]
        # set_reg(self.state, reg_no, tmp)
        set_reg2(self.state, reg_no, tmp)

class WriteByte(SimProcedure):
    # Write a byte to stdout from the specified register
    def run(self, reg_no): 
        reg = get_reg(self.state, reg_no)
        by = reg.get_byte(3)
        self.state.posix.fd[1].write_data(by, 1)

P['vmcastle'] = {}
P['vmcastle']['readbyte'] = ReadByte
P['vmcastle']['writebyte'] = WriteByte


syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('vmcastle')
syscall_lib.add_all_from_dict(P['vmcastle'])
syscall_lib.add_number_mapping_from_dict('vmcastle', {
    0 : 'readbyte',
    1 : 'writebyte',
    })


class SimVMCASTLE(SimUserland):
    """
    Defines the "OS" of a vmcastle program.

    This means:
    -  The memory layout (separate code and data)
    -  The "syscalls" (read stdin and write stdout)
    -  The calling convention (params, return, etc.)
    """

    def __init__(self, project, **kwargs):
        super(SimVMCASTLE, self).__init__(
            project,
            syscall_library=L['vmcastle'],
            syscall_addr_alignment=8,
            name='vmcastle',
            **kwargs)

    def state_blank(self, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimVMCASTLE, self).state_blank(
            stack_size=1024,
            stack_end=0x10005840,
            **kwargs)  # pylint:disable=invalid-name

        # Init other registers besides SP
        

        # allocate stack space if the stack doesn't "grow down"
        state.memory.map_region(state.regs.sp, 1024, 3, init_zero=True)
        
        return state

    def state_entry(self, **kwargs):
        state = super(SimVMCASTLE, self).state_entry(**kwargs)
        return state


class SimCCVMCASTLESyscall(SimCCSyscall):
    ARG_REGS = ['reg_no']
    
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = ArchVMCASTLE

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.sysnum


register_simos('vmcastle', SimVMCASTLE)
register_syscall_cc('vmcastle','vmcastle', SimCCVMCASTLESyscall)
# register_syscall_cc('vmcastle','default', SimCCVMCASTLESyscall)
register_default_cc('vmcastle',SimCCUnknown)
