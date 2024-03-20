#add various Hyper-V types
#@zenbassi 
#@category Hyper-V

from ghidra.program.model.data import *

""" take function and make a type name out of it """
def get_type_name(f):
    return f.__name__.upper()

""" get a type adding function and check if the type already exists """
def type_exists(type_f):
    type_name = get_type_name(type_f)
    return dt_mgr.findDataType("/" + type_name) is not None

####################################
##### TYPE ADDING FUNCTIONS ########
####################################

def add_success(name):
    print("{} added successfully".format(name))

def hv_eventlog_type(name):
    enum = EnumDataType(name, 1)
    enum.add("HvEventLogTypeGlobalSystemEvents", 0x0)
    enum.add("HvEventLogTypeLocalDiagnostics"  , 0x1)
    enum.add("HvEventLogTypeSystemDiagnostics" , 0x2)
    enum.add("HvEventLogTypeMaximum"           , 0x3)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)


def hv_eventlog_buffer_state(name):
    enum = EnumDataType(name, 1)
    enum.add("HvEventLogBufferStateStandby" , 0)
    enum.add("HvEventLogBufferStateFree"    , 1)
    enum.add("HvEventLogBufferStateInUse"   , 2)
    enum.add("HvEventLogBufferStateComplete", 3)
    enum.add("HvEventLogBufferStateReady"   , 4)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)

def hv_hypercall_table_entry(name):
    struct = StructureDataType(name, 0)
    struct.add(QWordDataType(), 8, "handler_routine_fp", "")
    struct.add(WordDataType(), 2, "hypercall_id", "")
    struct.add(WordDataType(), 2, "is_rep_call", "")
    struct.add(WordDataType(), 2, "no_rep_input_param_size", "")
    struct.add(WordDataType(), 2, "rep_input_param_size_rep", "")
    struct.add(WordDataType(), 2, "no_rep_output_param_size", "")
    struct.add(WordDataType(), 2, "rep_output_param_size", "")

    dt_mgr = currentProgram.dataTypeManager
    dt = dt_mgr.findDataType("/" + 'HV_HYPERCALL_STATS_GROUP')
    struct.add(dt, 2, "statistical_hypercall_group_number", "")
    struct.add(WordDataType(), 2, "padding", "")

    currentProgram.dataTypeManager.addDataType(struct, None)
    add_success(name)

def hv_hypercall_stats_group(name):
    win_20h1_offset = 3
    enum = EnumDataType(name, 2)
    enum.add("GPA_SPACE_HYPERCALL"                    , 0x3D + win_20h1_offset)
    enum.add("LOGICAL_PROCESSOR_HYPERCALL"            , 0x3E + win_20h1_offset)
    enum.add("LONG_SPIN_WAIT_HYPERCALL"               , 0x3F + win_20h1_offset)
    enum.add("OTHER_HYPERCALL"                        , 0x40 + win_20h1_offset)
    # i don't see same counter in PerformanceMonitor, but there is category in Hyper-v TLFS.
    enum.add("INTER_PARTITION_COMMUNICATION_HYPERCALL", 0x41 + win_20h1_offset)
    enum.add("VIRTUAL_INTERRUPT_HYPERCALL"            , 0x42 + win_20h1_offset)
    enum.add("VIRTUAL_MMU_HYPERCALL"                  , 0x43 + win_20h1_offset)
    enum.add("VIRTUAL_PROCESSOR_HYPERCALL"            , 0x44 + win_20h1_offset)
    enum.add("VIRTUAL_PROCESSOR_HYPERCALL02"          , 0x45 + win_20h1_offset)
    enum.add("FLUSH_PHYSICAL_ADDRESS_SPACE"           , 0x8F + win_20h1_offset)
    enum.add("FLUSH_PHYSICAL_ADDRESS_LIST"            , 0x90 + win_20h1_offset)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)

# hvcall (return) status codes name to value dict
hvcall_return_status_codes_dict = {
    "HV_STATUS_SUCCESS": 0x0000,
    "Reserved00": 0x0001,
    "HV_STATUS_INVALID_HVCALL_CODE": 0x0002,
    "HV_STATUS_INVALID_HVCALL_INPUT": 0x0003,
    "HV_STATUS_INVALID_ALIGNMENT": 0x0004,
    "HV_STATUS_INVALID_PARAMETER": 0x0005,
    "HV_STATUS_ACCESS_DENIED": 0x0006,
    "HV_STATUS_INVALID_PARTITION_STATE": 0x0007,
    "HV_STATUS_OPERATION_DENIED": 0x0008,
    "HV_STATUS_UNKNOWN_PROPERTY": 0x0009,
    "HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE": 0x000A,
    "HV_STATUS_INSUFFICIENT_MEMORY": 0x000B,
    "HV_STATUS_PARTITION_TOO_DEEP": 0x000C,
    "HV_STATUS_INVALID_PARTITION_ID": 0x000D,
    "HV_STATUS_INVALID_VP_INDEX": 0x000E,
    "Reserved01": 0x000F,
    "Reserved02": 0x0010,
    "HV_STATUS_INVALID_PORT_ID": 0x0011,
    "HV_STATUS_INVALID_CONNECTION_ID": 0x0012,
    "HV_STATUS_INSUFFICIENT_BUFFERS": 0x0013,
    "HV_STATUS_NOT_ACKNOWLEDGED": 0x0014,
    "HV_STATUS_INVALID_VP_STATE": 0x0015,
    "HV_STATUS_ACKNOWLEDGED": 0x0016,
    "HV_STATUS_INVALID_SAVE_RESTORE_STATE": 0x0017,
    "HV_STATUS_INVALID_SYNIC_STATE": 0x0018,
    "HV_STATUS_OBJECT_IN_USE": 0x0019,
    "HV_STATUS_INVALID_PROXIMITY_DOMAIN_INFO": 0x001A,
    "HV_STATUS_NO_DATA": 0x001B,
    "HV_STATUS_INACTIVE": 0x001C,
    "HV_STATUS_NO_RESOURCES": 0x001D,
    "HV_STATUS_FEATURE_UNAVAILABLE": 0x001E,
    "HV_STATUS_PARTIAL_PACKET": 0x001F,
    "HV_STATUS_PROCESSOR_FEATURE_NOT_SUPPORTED": 0x0020,
    "HV_STATUS_PROCESSOR_CACHE_LINE_FLUSH_SIZE_INCOMPATIBLE": 0x0030,
    "HV_STATUS_INSUFFICIENT_BUFFER": 0x0033,
    "HV_STATUS_INCOMPATIBLE_PROCESSOR": 0x0037,
    "HV_STATUS_INSUFFICIENT_DEVICE_DOMAINS": 0x0038,
    "HV_STATUS_CPUID_FEATURE_VALIDATION_ERROR": 0x003C,
    "HV_STATUS_CPUID_XSAVE_FEATURE_VALIDATION_ERROR": 0x003D,
    "HV_STATUS_PROCESSOR_STARTUP_TIMEOUT": 0x003E,
    "HV_STATUS_SMX_ENABLED": 0x003F,
    "HV_STATUS_INVALID_LP_INDEX": 0x0041,
    "HV_STATUS_INVALID_REGISTER_VALUE": 0x0050,
    "HV_STATUS_NX_NOT_DETECTED": 0x0055,
    "HV_STATUS_INVALID_DEVICE_ID": 0x0057,
    "HV_STATUS_INVALID_DEVICE_STATE": 0x0058,
    "HV_STATUS_PENDING_PAGE_REQUESTS": 0x0059,
    "HV_STATUS_PAGE_REQUEST_INVALID": 0x0060,
    "HV_STATUS_OPERATION_FAILED": 0x0071,
    "HV_STATUS_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE": 0x0072
} # extracted from: Hypervisor Top Level Functional Specification v6.0b

# each hypercall returns an HV_STATUS
# this functions defines the HV_STATUS enum
def hv_status(name):
    enum = EnumDataType(name, 2)
    for k, v in hvcall_return_status_codes_dict.items():
        enum.add(k, v)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)

types_list = [
    hv_eventlog_type,
    hv_eventlog_buffer_state,
    hv_hypercall_stats_group,
    hv_hypercall_table_entry,
    hv_status,
]

dt_mgr = currentProgram.dataTypeManager

for type_f in types_list:
    type_name = get_type_name(type_f)
    if dt_mgr.findDataType("/" + type_name) is not None:
	print("%s already exists" % type_name)
        continue
    type_f(type_name)
