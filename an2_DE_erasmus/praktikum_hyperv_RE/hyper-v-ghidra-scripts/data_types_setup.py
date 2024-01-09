#add varios Hyper-V types
#@zenbassi 
#@category Hyper-V

from ghidra.program.model.data import EnumDataType

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
    enum = EnumDataType(name, 8)
    enum.add("HvEventLogTypeGlobalSystemEvents", 0x0)
    enum.add("HvEventLogTypeLocalDiagnostics"  , 0x1)
    enum.add("HvEventLogTypeSystemDiagnostics" , 0x2)
    enum.add("HvEventLogTypeMaximum"           , 0x2)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)


def hv_eventlog_buffer_state(name):
    enum = EnumDataType(name, 8)
    enum.add("HvEventLogBufferStateStandby" , 0)
    enum.add("HvEventLogBufferStateFree"    , 1)
    enum.add("HvEventLogBufferStateInUse"   , 2)
    enum.add("HvEventLogBufferStateComplete", 3)
    enum.add("HvEventLogBufferStateReady"   , 4)
    currentProgram.dataTypeManager.addDataType(enum, None)
    add_success(name)


types_list = [
    hv_eventlog_type,
    hv_eventlog_buffer_state,
]

dt_mgr = currentProgram.dataTypeManager

for type_f in types_list:
    type_name = get_type_name(type_f)
    if dt_mgr.findDataType("/" + type_name) is not None:
        continue
    type_f(type_name)
