#assign name and return type to each hypercall
#@zenbassi 
#@category Hyper-V

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import EnumDataType

# hyper-v hvcalls names
hvcalls_dict = {
    0x0000: 'HvCallReserved00',
    0x0001: 'HvCallSwitchVirtualAddressSpace',
    0x0002: 'HvCallFlushVirtualAddressSpace',
    0x0003: 'HvCallFlushVirtualAddressList',
    0x0004: 'HvCallGetLogicalProcessorRunTime',
    0x0005: 'HvCallUpdateHvProcessorFeatures',              #winhvr.sys (09.2019)
    0x0006: 'HvCallSwitchAliasMap',
    0x0007: 'HvCallUpdateMicrocodeDatabase',                #ntoskrnl.exe, HvDynamicUpdateMicrocode has same microcode
    0x0008: 'HvCallNotifyLongSpinWait',
    0x0009: 'HvCallParkedLogicalProcessors',
    0x000a: 'HvCallInvokeHypervisorDebugger',
    #2016
    0x000b: 'HvCallSendSyntheticClusterIpi',                #SkpgPatchGuardCallbackRoutine
    0x000c: 'HvCallModifyVtlProtectionMask',
    0x000d: 'HvCallEnablePartitionVtl',
    0x000e: 'HvCallDisablePartitionVtl',
    0x000f: 'HvCallEnableVpVtl',
    0x0010: 'HvCallDisableVpVtl',
    0x0011: 'HvCallVtlCall',
    0x0012: 'HvCallVtlReturn',
    0x0013: 'HvCallFlushVirtualAddressSpaceEx',
    0x0014: 'HvCallFlushVirtualAddressListEx',
    0x0015: 'HvCallSendSyntheticClusterIpiEx',              #securekernel.exe, SkpgPatchGuardCallbackRoutine
    #####
    0x0016: 'HvCallQueryImageInfo',
    0x0017: 'HvCallMapPatchPages',                          #securekernel.exe, ShvlLoadHypervisorPatch
    0x0018: 'HvCallCommitPatch',                            #securekernel.exe, ShvlLoadHypervisorPatch
    0x0019: 'HvCallSyncContext',
    0x001a: 'HvCallSyncContextEx',
    0x001b: 'HvCallReadPerfRegister',
    0x001c: 'HvCallWritePerfRegister',                      #ntoskrnl.exe, Fast hvcall
    0x001d: 'HvCallReserved01',
    0x001e: 'HvCallReserved02',
    0x001f: 'HvCallReserved03',
    0x0020: 'HvCallReserved04',
    0x0021: 'HvCallReserved05',
    0x0022: 'HvCallReserved06',
    0x0023: 'HvCallReserved07',
    0x0024: 'HvCallReserved08',
    0x0025: 'HvCallReserved09',
    0x0026: 'HvCallReserved10',
    0x0027: 'HvCallReserved11',
    0x0028: 'HvCallReserved12',
    0x0029: 'HvCallReserved13',
    0x002a: 'HvCallReserved14',
    0x002b: 'HvCallReserved15',
    0x002c: 'HvCallReserved16',
    0x002d: 'HvCallReserved17',
    0x002e: 'HvCallReserved18',
    0x002f: 'HvCallReserved19',
    0x0030: 'HvCallReserved20',
    0x0031: 'HvCallReserved21',
    0x0032: 'HvCallReserved22',
    0x0033: 'HvCallReserved23',
    0x0034: 'HvCallReserved24',
    0x0035: 'HvCallReserved25',
    0x0036: 'HvCallReserved26',
    0x0037: 'HvCallReserved27',
    0x0038: 'HvCallReserved28',
    0x0039: 'HvCallReserved29',
    0x003a: 'HvCallReserved30',
    0x003b: 'HvCallReserved31',
    0x003c: 'HvCallReserved32',
    0x003d: 'HvCallReserved34',
    0x003e: 'HvCallReserved34',
    0x003f: 'HvCallReserved35',
    0x0040: 'HvCallCreatePartition',
    0x0041: 'HvCallInitializePartition',
    0x0042: 'HvCallFinalizePartition',
    0x0043: 'HvCallDeletePartition',
    0x0044: 'HvCallGetPartitionProperty',
    0x0045: 'HvCallSetPartitionProperty',
    0x0046: 'HvCallGetPartitionId',
    0x0047: 'HvCallGetNextChildPartition',
    0x0048: 'HvCallDepositMemory',
    0x0049: 'HvCallWithdrawMemory',
    0x004A: 'HvCallGetMemoryBalance',
    0x004B: 'HvCallMapGpaPages',
    0x004C: 'HvCallUnmapGpaPages',
    0x004D: 'HvCallInstallIntercept',
    0x004E: 'HvCallCreateVp',
    0x004F: 'HvCallDeleteVp',
    0x0050: 'HvCallGetVpRegisters',
    0x0051: 'HvCallSetVpRegisters',
    0x0052: 'HvCallTranslateVirtualAddress',                #used by securekernel.exe
    0x0053: 'HvCallReadGpa',
    0x0054: 'HvCallWriteGpa',
    0x0055: 'HvCallAssertVirtualInterruptDeprecated',                             #depricated
    0x0056: 'HvCallClearVirtualInterrupt',
    0x0057: 'HvCallCreatePortDeprecated',
    0x0058: 'HvCallDeletePort',
    0x0059: 'HvCallConnectPortDeprecated',
    0x005A: 'HvCallGetPortProperty',
    0x005B: 'HvCallDisconnectPort',
    0x005C: 'HvCallPostMessage',
    0x005D: 'HvCallSignalEvent',
    0x005E: 'HvCallSavePartitionState',                     #HvCancelSavePartitionState in latest winhvr.sys (09.2019), HvSavePartitionState has same hvcall ID
    0x005F: 'HvCallRestorePartitionState',                  #HvCancelRestorePartitionState in latest winhvr.sys (09.2019)
    0x0060: 'HvCallInitializeEventLogBufferGroup',
    0x0061: 'HvCallFinalizeEventLogBufferGroup',
    0x0062: 'HvCallCreateEventLogBuffer',
    0x0063: 'HvCallDeleteEventLogBuffer',
    0x0064: 'HvCallMapEventLogBuffer',
    0x0065: 'HvCallUnmapEventLogBuffer',
    0x0066: 'HvCallSetEventLogGroupSources',
    0x0067: 'HvCallReleaseEventLogBuffer',
    0x0068: 'HvCallFlushEventLogBuffer',
    0x0069: 'HvCallPostDebugData',
    0x006A: 'HvCallRetrieveDebugData',
    0x006B: 'HvCallResetDebugSession',
    0x006C: 'HvCallMapStatsPage',
    0x006D: 'HvCallUnmapStatsPage',
    0x006E: 'HvCallMapSparseGpaPages',
    0x006F: 'HvCallSetSystemProperty',                      #HvConfigureProfiler, HvSetHvDebugProperty we can see in winhvr.sys (09.2019)
    0x0070: 'HvCallSetPortProperty',
    0x0071: 'HvCallOutputDebugCharacter',
    0x0072: 'HvCallEchoIncrement',
    0x0073: 'HvCallPerfNop',
    0x0074: 'HvCallPerfNopInput',
    0x0075: 'HvCallPerfNopOutput',
    0x0076: 'HvCallAddLogicalProcessor',
    0x0077: 'HvCallRemoveLogicalProcessor',
    0x0078: 'HvCallQueryNumaDistance',
    0x0079: 'HvCallSetLogicalProcessorProperty',
    0x007A: 'HvCallGetLogicalProcessorProperty',
    0x007B: 'HvCallGetSystemProperty',                      #HvGetSystemInformation in winhvr.sys (09.2019)
    0x007C: 'HvCallMapDeviceInterrupt',
    0x007D: 'HvCallUnmapDeviceInterrupt',
    0x007E: 'HvCallRetargetDeviceInterrupt',                #renamed
    0x007F: 'HvCallRetargetRootDeviceInterrupt',            #made reserved
    0x0080: 'HvCallMapDevicePages',                         #HvAssertDeviceInterrupt in winhvr.sys (09.2019). HvMapDevicePages is not present.
    0x0081: 'HvCallUnmapDevicePages',
    0x0082: 'HvCallAttachDevice',
    0x0083: 'HvCallDetachDevice',
    0x0084: 'HvCallEnterSleepState',
    0x0085: 'HvCallNotifyStandbyTransition',                        #HvNotifyStandbyTransition in winhvr.sys (09.2019)
    0x0086: 'HvCallPrepareForHibernate',
    0x0087: 'HvCallNotifyPartitionEvent',
    0x0088: 'HvCallGetLogicalProcessorRegisters',
    0x0089: 'HvCallSetLogicalProcessorRegisters',
    0x008A: 'HvCallQueryAssociatedLpsforMca',
    0x008B: 'HvCallNotifyRingEmpty',                        #HvGetNextQueuedPort in winhvr.sys (09.2019)
    0x008C: 'HvCallInjectSyntheticMachineCheck',
    0x008d: 'HvCallScrubPartition',
    0x008e: 'HvCallCollectLivedump',
    0x008f: 'HvCallDisableHypervisor',
    0x0090: 'HvCallModifySparseGpaPages',
    0x0091: 'HvCallRegisterInterceptResult',
    0x0092: 'HvCallUnregisterInterceptResult',
    #2016
    0x0093: 'HvCallGetCoverageData',
    0x0094: 'HvCallAssertVirtualInterrupt',
    0x0095: 'HvCallCreatePort',
    0x0096: 'HvCallConnectPort',
    0x0097: 'HvCallGetSpaPageList',
    0x0098: 'HvCallReserved36',
    0x0099: 'HvCallStartVirtualProcessor',
    0x009A: 'HvCallGetVpIndexFromApicId',
    0x009B: 'HvCallGetPowerProperty',
    0x009C: 'HvCallSetPowerProperty',
    0x009D: 'HvCallCreatePasidSpace',
    0x009E: 'HvCallDeletePasidSpace',
    0x009F: 'HvCallSetPasidAddressSpace',
    0x00A0: 'HvCallFlushPasidAddressSpace',
    0x00A1: 'HvCallFlushPasidAddressList',
    0x00A2: 'HvCallAttachPasidSpace',
    0x00A3: 'HvCallDetachPasidSpace',
    0x00A4: 'HvCallEnablePasid',
    0x00A5: 'HvCallDisablePasid',
    0x00A6: 'HvCallAcknowledgePageRequest',
    0x00A7: 'HvCallCreateDevicePrQueue',
    0x00A8: 'HvCallDeleteDevicePrQueue',
    0x00A9: 'HvCallSetDevicePrqProperty',
    0x00AA: 'HvCallGetPhysicalDeviceProperty',
    0x00AB: 'HvCallSetPhysicalDeviceProperty',
    0x00AC: 'HvCallTranslateVirtualAddressEx',               #winhvr.sys. Early it has hvcall id 0x52
    0x00AD: 'HvCallCheckForIoIntercept',	                 #winhvr.sys
    0x00AE: 'HvCallSetGpaPageAttributes',                    #securekernel.exe
    0x00AF: 'HvCallFlushGuestPhysicalAddressSpace',
    0x00B0: 'HvCallFlushGuestPhysicalAddressList',
    #2019
    0x00B1: 'HvCallCreateDeviceDomain',
    0x00B2: 'HvCallAttachDeviceDomain',                      #securekernel.exe
    0x00B3: 'HvCallMapDeviceGpaPages',                       #securekernel.exe
    0x00B4: 'HvCallUnmapDeviceGpaPages',                     #securekernel.exe
    0x00B5: 'HvCallCreateCpuGroup',                          #winhvr.sys
    0x00B6: 'HvCallDeleteCpuGroup',                          #winhvr.sys
    0x00B7: 'HvCallGetCpuGroupProperty',                     #winhvr.sys
    0x00B8: 'HvCallSetCpuGroupProperty',                     #winhvr.sys
    0x00B9: 'HvCallGetCpuGroupAffinity',                     #winhvr.sys
    0x00BA: 'HvCallGetNextCpuGroup',                         #winhvr.sys
    0x00BB: 'HvCallGetNextCpuGroupPartition',                #winhvr.sys
    0x00BC: 'HvCallAddPhysicalMemory',
    0x00BD: 'HvCallCompleteIntercept',                       #winhvr.sys
    0x00BE: 'HvCallPrecommitGpaPages',                       #winhvr.sys
    0x00BF: 'HvCallUncommitGpaPages',                        #winhvr.sys
    0x00C0: 'HvCallReserved37',
    0x00C1: 'HvCallReserved38',
    0x00C2: 'HvCallDispatchVp',                              #winhvr.sys, fast hvcall
    0x00C3: 'HvCallProcessIommuPrq',
    0x00C4: 'HvCallDetachDeviceDomain',
    0x00C5: 'HvCallDeleteDeviceDomain',
    0x00C6: 'HvCallQueryDeviceDomain',
    0x00C7: 'HvCallMapSparseDeviceGpaPages',
    0x00C8: 'HvCallUnmapSparseDeviceGpaPages',
    0x00C9: 'HvCallGetGpaPagesAccessState',                  #winhvr.sys
    0x00CA: 'HvCallGetSparseGpaPagesAccessState',
    0x00CB: 'HvCallInvokeTestFramework',
    0x00CC: 'HvCallQueryVtlProtectionMaskRange',             #winhvr.sys
    0x00CD: 'HvCallModifyVtlProtectionMaskRange',            #winhvr.sys
    0x00CE: 'HvCallConfigureDeviceDomain',
    0x00CF: 'HvCallQueryDeviceDomainProperties',
    0x00D0: 'HvCallFlushDeviceDomain',
    0x00D1: 'HvCallFlushDeviceDomainList',
    0x00D2: 'HvCallAcquireSparseGpaPageHostAccess',          #winhvr.sys
    0x00D3: 'HvCallReleaseSparseGpaPageHostAccess',          #winhvr.sys
    0x00D4: 'HvCallCheckSparseGpaPageVtlAccess',             #winhvr.sys
    0x00D5: 'HvCallEnableDeviceInterrupt',
    0x00D6: 'HvCallFlushTlb',
    0x00D7: 'HvCallAcquireSparseSpaPageHostAccess',          #winhvr.sys
    0x00D8: 'HvCallUnacquireSparseSpaPageHostAccess',          #winhvr.sys
    0x00D9: 'HvCallAcceptGpaPages',                          #winhv.sys
    0x00DA: 'HvCallUnacceptGpaPages',
    0x00DB: 'HvCallModifySparseGpaPageHostVisibility',                          #winhvr.sys
    0x00DC: 'HvCallLockSparseGpaPageMapping',
    0x00DD: 'HvCallUnlockSparseGpaPageMapping',
    0x00DE: 'HvCallRequestProcessorHalt',
    0x00DF: 'HvCallGetInterceptData',
    0x00E0: 'HvCallQueryDeviceInterruptTarget',              #winhvr.sys
    0x00E1: 'HvCallMapVpStatePage',                          #winhvr.sys (HvMapVpStatePage in Windows 10)
    0x00E2: 'HvCallUnmapVpStatePage',
    0x00E3: 'HvCallGetXsaveData',                            #winhvr.sys
    0x00E4: 'HvCallSetXsaveData',                            #winhvr.sys
    0x00E5: 'HvCallGetLocalInterruptControllerState',        #winhvr.sys
    0x00E6: 'HvCallSetLocalInterruptControllerState',        #winhvr.sys
    0x00E7: 'HvCallCreateIptBuffers',                        #winhvr.sys (Windows 10)
    0x00E8: 'HvCallDeleteIptBuffers',                        #winhvr.sys (Windows 10)
    ## hvgdk.h
    0x00E9: 'HvCallControlHypervisorIptTrace',
    0x00EA: 'HvCallReserveDeviceInterrupt',
    0x00EB: 'HvCallPersistDevice',
    0x00EC: 'HvCallUnpersistDevice',
    0x00ED: 'HvCallPersistDeviceInterrupt',
    0x00EE: 'HvCallUpdatePerformanceStateCountersForLp',
} # extracted from: https://github.com/gerhart01/Hyper-V-scripts/blob/master/CreatemVmcallHandlersTable20H1.py

# hvcall (return) status codes name to value dict
hvcall_return_status_codes_dict = {
    "HV_STATUS_SUCCESS": 0x0000,
    "Reserved00": 0x0001,
    "HV_STATUS_INVALID_hvcall_CODE": 0x0002,
    "HV_STATUS_INVALID_hvcall_INPUT": 0x0003,
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

HVCALLS_BASE_ADDRESS = "0xfffff80000c00018"

# each hypercall returns an HV_STATUS
# this functions defines the HV_STATUS enum
def add_hvcall_status_codes_enum():
    enum = EnumDataType("HV_STATUS", 8)
    for k, v in hvcall_return_status_codes_dict.items():
        enum.add(k, v)
    currentProgram.dataTypeManager.addDataType(enum, None)


# for all hypercalls set it's name according to hvcalls_dict
# and the return type to HV_STATUS
def set_hvcall_names_and_return_types():
    dt_manager = currentProgram.dataTypeManager
    ret_type = dt_manager.findDataType("/HV_STATUS")

    hvcalls_base_address = toAddr(HVCALLS_BASE_ADDRESS)
    hvcalls_entry_table = getDataAt(hvcalls_base_address)
    hvcalls_cnt = hvcalls_entry_table.getNumComponents()
    hvcalls_data_type = hvcalls_entry_table.getComponentAt(0).getDataType()
    hvcall_entry_size = hvcalls_data_type.getLength()

    # iterate from 1 because call nr. 0 is not used
    # so we have a 1-indexed array
    for i in range(1, hvcalls_cnt + 1):
        entry = hvcalls_entry_table.getComponentAt((i - 1) * hvcall_entry_size)
        hvcall_address = toAddr(entry.getComponent(0).getValue().toString())
        hvcall = getFunctionAt(hvcall_address)
    if hvcall is None:
        # TODO there are some inconsistencies with the hvcall names - do figure
        # to avoid inconsistencies as much as possible I just made a placeholder name
        createFunction(hvcall_address, "place_holder_undefined")
    else:
        hvcall.setName(hvcalls_dict[i], SourceType.ANALYSIS)
        hvcall.setReturnType(ret_type, SourceType.ANALYSIS)

add_hvcall_status_codes_enum()
set_hvcall_names_and_return_types()
