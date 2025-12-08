// 0x840 bytes (sizeof)
struct _EPROCESS {
  struct _KPROCESS Pcb;                  // 0x0
  struct _EX_PUSH_LOCK ProcessLock;      // 0x1c8
  VOID *UniqueProcessId;                 // 0x1d0
  struct _LIST_ENTRY ActiveProcessLinks; // 0x1d8
  struct _EX_RUNDOWN_REF RundownProtect; // 0x1e8
  union {
    ULONG Flags2; // 0x1f0
    struct {
      ULONG JobNotReallyActive : 1;              // 0x1f0
      ULONG AccountingFolded : 1;                // 0x1f0
      ULONG NewProcessReported : 1;              // 0x1f0
      ULONG ExitProcessReported : 1;             // 0x1f0
      ULONG ReportCommitChanges : 1;             // 0x1f0
      ULONG LastReportMemory : 1;                // 0x1f0
      ULONG ForceWakeCharge : 1;                 // 0x1f0
      ULONG CrossSessionCreate : 1;              // 0x1f0
      ULONG NeedsHandleRundown : 1;              // 0x1f0
      ULONG RefTraceEnabled : 1;                 // 0x1f0
      ULONG PicoCreated : 1;                     // 0x1f0
      ULONG EmptyJobEvaluated : 1;               // 0x1f0
      ULONG DefaultPagePriority : 3;             // 0x1f0
      ULONG PrimaryTokenFrozen : 1;              // 0x1f0
      ULONG ProcessVerifierTarget : 1;           // 0x1f0
      ULONG RestrictSetThreadContext : 1;        // 0x1f0
      ULONG AffinityPermanent : 1;               // 0x1f0
      ULONG AffinityUpdateEnable : 1;            // 0x1f0
      ULONG PropagateNode : 1;                   // 0x1f0
      ULONG ExplicitAffinity : 1;                // 0x1f0
      ULONG Flags2Available1 : 2;                // 0x1f0
      ULONG EnableReadVmLogging : 1;             // 0x1f0
      ULONG EnableWriteVmLogging : 1;            // 0x1f0
      ULONG FatalAccessTerminationRequested : 1; // 0x1f0
      ULONG DisableSystemAllowedCpuSet : 1;      // 0x1f0
      ULONG Flags2Available2 : 3;                // 0x1f0
      ULONG InPrivate : 1;                       // 0x1f0
    };
  };
  union {
    ULONG Flags; // 0x1f4
    struct {
      ULONG CreateReported : 1;               // 0x1f4
      ULONG NoDebugInherit : 1;               // 0x1f4
      ULONG ProcessExiting : 1;               // 0x1f4
      ULONG ProcessDelete : 1;                // 0x1f4
      ULONG ManageExecutableMemoryWrites : 1; // 0x1f4
      ULONG VmDeleted : 1;                    // 0x1f4
      ULONG OutswapEnabled : 1;               // 0x1f4
      ULONG Outswapped : 1;                   // 0x1f4
      ULONG FailFastOnCommitFail : 1;         // 0x1f4
      ULONG Wow64VaSpace4Gb : 1;              // 0x1f4
      ULONG AddressSpaceInitialized : 2;      // 0x1f4
      ULONG SetTimerResolution : 1;           // 0x1f4
      ULONG BreakOnTermination : 1;           // 0x1f4
      ULONG DeprioritizeViews : 1;            // 0x1f4
      ULONG WriteWatch : 1;                   // 0x1f4
      ULONG ProcessInSession : 1;             // 0x1f4
      ULONG OverrideAddressSpace : 1;         // 0x1f4
      ULONG HasAddressSpace : 1;              // 0x1f4
      ULONG LaunchPrefetched : 1;             // 0x1f4
      ULONG Reserved : 1;                     // 0x1f4
      ULONG VmTopDown : 1;                    // 0x1f4
      ULONG ImageNotifyDone : 1;              // 0x1f4
      ULONG PdeUpdateNeeded : 1;              // 0x1f4
      ULONG VdmAllowed : 1;                   // 0x1f4
      ULONG ProcessRundown : 1;               // 0x1f4
      ULONG ProcessInserted : 1;              // 0x1f4
      ULONG DefaultIoPriority : 3;            // 0x1f4
      ULONG ProcessSelfDelete : 1;            // 0x1f4
      ULONG SetTimerResolutionLink : 1;       // 0x1f4
    };
  };
  union _LARGE_INTEGER CreateTime;        // 0x1f8
  ULONGLONG ProcessQuotaUsage[2];         // 0x200
  ULONGLONG ProcessQuotaPeak[2];          // 0x210
  ULONGLONG PeakVirtualSize;              // 0x220
  ULONGLONG VirtualSize;                  // 0x228
  struct _LIST_ENTRY SessionProcessLinks; // 0x230
  union {
    VOID *ExceptionPortData;          // 0x240
    ULONGLONG ExceptionPortValue;     // 0x240
    ULONGLONG ExceptionPortState : 3; // 0x240
  };
  struct _EX_FAST_REF Token;                                          // 0x248
  ULONGLONG MmReserved;                                               // 0x250
  struct _EX_PUSH_LOCK AddressCreationLock;                           // 0x258
  struct _EX_PUSH_LOCK PageTableCommitmentLock;                       // 0x260
  struct _ETHREAD *RotateInProgress;                                  // 0x268
  struct _ETHREAD *ForkInProgress;                                    // 0x270
  struct _EJOB *volatile CommitChargeJob;                             // 0x278
  struct _RTL_AVL_TREE CloneRoot;                                     // 0x280
  volatile ULONGLONG NumberOfPrivatePages;                            // 0x288
  volatile ULONGLONG NumberOfLockedPages;                             // 0x290
  VOID *Win32Process;                                                 // 0x298
  struct _EJOB *volatile Job;                                         // 0x2a0
  VOID *SectionObject;                                                // 0x2a8
  VOID *SectionBaseAddress;                                           // 0x2b0
  ULONG Cookie;                                                       // 0x2b8
  struct _PAGEFAULT_HISTORY *WorkingSetWatch;                         // 0x2c0
  VOID *Win32WindowStation;                                           // 0x2c8
  VOID *InheritedFromUniqueProcessId;                                 // 0x2d0
  volatile ULONGLONG OwnerProcessId;                                  // 0x2d8
  struct _PEB *Peb;                                                   // 0x2e0
  struct _PSP_SESSION_SPACE *Session;                                 // 0x2e8
  VOID *Spare1;                                                       // 0x2f0
  struct _EPROCESS_QUOTA_BLOCK *QuotaBlock;                           // 0x2f8
  struct _HANDLE_TABLE *ObjectTable;                                  // 0x300
  VOID *DebugPort;                                                    // 0x308
  struct _EWOW64PROCESS *WoW64Process;                                // 0x310
  struct _EX_FAST_REF DeviceMap;                                      // 0x318
  VOID *EtwDataSource;                                                // 0x320
  ULONGLONG PageDirectoryPte;                                         // 0x328
  struct _FILE_OBJECT *ImageFilePointer;                              // 0x330
  UCHAR ImageFileName[15];                                            // 0x338
  UCHAR PriorityClass;                                                // 0x347
  VOID *SecurityPort;                                                 // 0x348
  struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;  // 0x350
  struct _LIST_ENTRY JobLinks;                                        // 0x358
  VOID *HighestUserAddress;                                           // 0x368
  struct _LIST_ENTRY ThreadListHead;                                  // 0x370
  volatile ULONG ActiveThreads;                                       // 0x380
  ULONG ImagePathHash;                                                // 0x384
  ULONG DefaultHardErrorProcessing;                                   // 0x388
  LONG LastThreadExitStatus;                                          // 0x38c
  struct _EX_FAST_REF PrefetchTrace;                                  // 0x390
  VOID *LockedPagesList;                                              // 0x398
  union _LARGE_INTEGER ReadOperationCount;                            // 0x3a0
  union _LARGE_INTEGER WriteOperationCount;                           // 0x3a8
  union _LARGE_INTEGER OtherOperationCount;                           // 0x3b0
  union _LARGE_INTEGER ReadTransferCount;                             // 0x3b8
  union _LARGE_INTEGER WriteTransferCount;                            // 0x3c0
  union _LARGE_INTEGER OtherTransferCount;                            // 0x3c8
  ULONGLONG CommitChargeLimit;                                        // 0x3d0
  volatile ULONGLONG CommitCharge;                                    // 0x3d8
  volatile ULONGLONG CommitChargePeak;                                // 0x3e0
  struct _MMSUPPORT_FULL Vm;                                          // 0x400
  struct _LIST_ENTRY MmProcessLinks;                                  // 0x540
  volatile ULONG ModifiedPageCount;                                   // 0x550
  LONG ExitStatus;                                                    // 0x554
  struct _RTL_AVL_TREE VadRoot;                                       // 0x558
  VOID *VadHint;                                                      // 0x560
  ULONGLONG VadCount;                                                 // 0x568
  volatile ULONGLONG VadPhysicalPages;                                // 0x570
  ULONGLONG VadPhysicalPagesLimit;                                    // 0x578
  struct _ALPC_PROCESS_CONTEXT AlpcContext;                           // 0x580
  struct _LIST_ENTRY TimerResolutionLink;                             // 0x5a0
  struct _PO_DIAG_STACK_RECORD *TimerResolutionStackRecord;           // 0x5b0
  ULONG RequestedTimerResolution;                                     // 0x5b8
  ULONG SmallestTimerResolution;                                      // 0x5bc
  union _LARGE_INTEGER ExitTime;                                      // 0x5c0
  struct _INVERTED_FUNCTION_TABLE_KERNEL_MODE *InvertedFunctionTable; // 0x5c8
  struct _EX_PUSH_LOCK InvertedFunctionTableLock;                     // 0x5d0
  ULONG ActiveThreadsHighWatermark;                                   // 0x5d8
  ULONG LargePrivateVadCount;                                         // 0x5dc
  struct _EX_PUSH_LOCK ThreadListLock;                                // 0x5e0
  VOID *WnfContext;                                                   // 0x5e8
  struct _EJOB *ServerSilo;                                           // 0x5f0
  UCHAR SignatureLevel;                                               // 0x5f8
  UCHAR SectionSignatureLevel;                                        // 0x5f9
  struct _PS_PROTECTION Protection;                                   // 0x5fa
  UCHAR HangCount : 3;                                                // 0x5fb
  UCHAR GhostCount : 3;                                               // 0x5fb
  UCHAR PrefilterException : 1;                                       // 0x5fb
  union {
    ULONG Flags3; // 0x5fc
    struct {
      ULONG Minimal : 1;                                 // 0x5fc
      ULONG ReplacingPageRoot : 1;                       // 0x5fc
      ULONG Crashed : 1;                                 // 0x5fc
      ULONG JobVadsAreTracked : 1;                       // 0x5fc
      ULONG VadTrackingDisabled : 1;                     // 0x5fc
      ULONG AuxiliaryProcess : 1;                        // 0x5fc
      ULONG SubsystemProcess : 1;                        // 0x5fc
      ULONG IndirectCpuSets : 1;                         // 0x5fc
      ULONG RelinquishedCommit : 1;                      // 0x5fc
      ULONG HighGraphicsPriority : 1;                    // 0x5fc
      ULONG CommitFailLogged : 1;                        // 0x5fc
      ULONG ReserveFailLogged : 1;                       // 0x5fc
      ULONG SystemProcess : 1;                           // 0x5fc
      ULONG AllImagesAtBasePristineBase : 1;             // 0x5fc
      ULONG AddressPolicyFrozen : 1;                     // 0x5fc
      ULONG ProcessFirstResume : 1;                      // 0x5fc
      ULONG ForegroundExternal : 1;                      // 0x5fc
      ULONG ForegroundSystem : 1;                        // 0x5fc
      ULONG HighMemoryPriority : 1;                      // 0x5fc
      ULONG EnableProcessSuspendResumeLogging : 1;       // 0x5fc
      ULONG EnableThreadSuspendResumeLogging : 1;        // 0x5fc
      ULONG SecurityDomainChanged : 1;                   // 0x5fc
      ULONG SecurityFreezeComplete : 1;                  // 0x5fc
      ULONG VmProcessorHost : 1;                         // 0x5fc
      ULONG VmProcessorHostTransition : 1;               // 0x5fc
      ULONG AltSyscall : 1;                              // 0x5fc
      ULONG TimerResolutionIgnore : 1;                   // 0x5fc
      ULONG DisallowUserTerminate : 1;                   // 0x5fc
      ULONG EnableProcessRemoteExecProtectVmLogging : 1; // 0x5fc
      ULONG EnableProcessLocalExecProtectVmLogging : 1;  // 0x5fc
      ULONG MemoryCompressionProcess : 1;                // 0x5fc
      ULONG EnableProcessImpersonationLogging : 1;       // 0x5fc
    };
  };
  LONG DeviceAsid;                                  // 0x600
  VOID *SvmData;                                    // 0x608
  struct _EX_PUSH_LOCK SvmProcessLock;              // 0x610
  ULONGLONG SvmLock;                                // 0x618
  struct _LIST_ENTRY SvmProcessDeviceListHead;      // 0x620
  ULONGLONG LastFreezeInterruptTime;                // 0x630
  struct _PROCESS_DISK_COUNTERS *DiskCounters;      // 0x638
  VOID *PicoContext;                                // 0x640
  VOID *EnclaveTable;                               // 0x648
  ULONGLONG EnclaveNumber;                          // 0x650
  struct _EX_PUSH_LOCK EnclaveLock;                 // 0x658
  ULONG HighPriorityFaultsAllowed;                  // 0x660
  struct _PO_PROCESS_ENERGY_CONTEXT *EnergyContext; // 0x668
  VOID *VmContext;                                  // 0x670
  ULONGLONG SequenceNumber;                         // 0x678
  ULONGLONG CreateInterruptTime;                    // 0x680
  ULONGLONG CreateUnbiasedInterruptTime;            // 0x688
  ULONGLONG TotalUnbiasedFrozenTime;                // 0x690
  ULONGLONG LastAppStateUpdateTime;                 // 0x698
  ULONGLONG LastAppStateUptime : 61;                // 0x6a0
  ULONGLONG LastAppState : 3;                       // 0x6a0
  volatile ULONGLONG SharedCommitCharge;            // 0x6a8
  struct _EX_PUSH_LOCK SharedCommitLock;            // 0x6b0
  struct _LIST_ENTRY SharedCommitLinks;             // 0x6b8
  union {
    struct {
      ULONGLONG AllowedCpuSets; // 0x6c8
      ULONGLONG DefaultCpuSets; // 0x6d0
    };
    struct {
      ULONGLONG *AllowedCpuSetsIndirect; // 0x6c8
      ULONGLONG *DefaultCpuSetsIndirect; // 0x6d0
    };
  };
  VOID *DiskIoAttribution;                                            // 0x6d8
  VOID *DxgProcess;                                                   // 0x6e0
  ULONG Win32KFilterSet;                                              // 0x6e8
  USHORT Machine;                                                     // 0x6ec
  UCHAR MmSlabIdentity;                                               // 0x6ee
  UCHAR Spare0;                                                       // 0x6ef
  unionvolatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay; // 0x6f0
  volatile ULONG KTimerSets;                                          // 0x6f8
  volatile ULONG KTimer2Sets;                                         // 0x6fc
  volatile ULONG ThreadTimerSets;                                     // 0x700
  ULONGLONG VirtualTimerListLock;                                     // 0x708
  struct _LIST_ENTRY VirtualTimerListHead;                            // 0x710
  union {
    struct _WNF_STATE_NAME WakeChannel;           // 0x720
    struct _PS_PROCESS_WAKE_INFORMATION WakeInfo; // 0x720
  };
  union {
    ULONG MitigationFlags; // 0x750
    struct {
      ULONG ControlFlowGuardEnabled : 1;                  // 0x750
      ULONG ControlFlowGuardExportSuppressionEnabled : 1; // 0x750
      ULONG ControlFlowGuardStrict : 1;                   // 0x750
      ULONG DisallowStrippedImages : 1;                   // 0x750
      ULONG ForceRelocateImages : 1;                      // 0x750
      ULONG HighEntropyASLREnabled : 1;                   // 0x750
      ULONG StackRandomizationDisabled : 1;               // 0x750
      ULONG ExtensionPointDisable : 1;                    // 0x750
      ULONG DisableDynamicCode : 1;                       // 0x750
      ULONG DisableDynamicCodeAllowOptOut : 1;            // 0x750
      ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;   // 0x750
      ULONG AuditDisableDynamicCode : 1;                  // 0x750
      ULONG DisallowWin32kSystemCalls : 1;                // 0x750
      ULONG AuditDisallowWin32kSystemCalls : 1;           // 0x750
      ULONG EnableFilteredWin32kAPIs : 1;                 // 0x750
      ULONG AuditFilteredWin32kAPIs : 1;                  // 0x750
      ULONG DisableNonSystemFonts : 1;                    // 0x750
      ULONG AuditNonSystemFontLoading : 1;                // 0x750
      ULONG PreferSystem32Images : 1;                     // 0x750
      ULONG ProhibitRemoteImageMap : 1;                   // 0x750
      ULONG AuditProhibitRemoteImageMap : 1;              // 0x750
      ULONG ProhibitLowILImageMap : 1;                    // 0x750
      ULONG AuditProhibitLowILImageMap : 1;               // 0x750
      ULONG SignatureMitigationOptIn : 1;                 // 0x750
      ULONG AuditBlockNonMicrosoftBinaries : 1;           // 0x750
      ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1; // 0x750
      ULONG LoaderIntegrityContinuityEnabled : 1;         // 0x750
      ULONG AuditLoaderIntegrityContinuity : 1;           // 0x750
      ULONG EnableModuleTamperingProtection : 1;          // 0x750
      ULONG EnableModuleTamperingProtectionNoInherit : 1; // 0x750
      ULONG RestrictIndirectBranchPrediction : 1;         // 0x750
      ULONG IsolateSecurityDomain : 1;                    // 0x750
    } MitigationFlagsValues;                              // 0x750
  };
  union {
    ULONG MitigationFlags2; // 0x754
    struct {
      ULONG EnableExportAddressFilter : 1;                // 0x754
      ULONG AuditExportAddressFilter : 1;                 // 0x754
      ULONG EnableExportAddressFilterPlus : 1;            // 0x754
      ULONG AuditExportAddressFilterPlus : 1;             // 0x754
      ULONG EnableRopStackPivot : 1;                      // 0x754
      ULONG AuditRopStackPivot : 1;                       // 0x754
      ULONG EnableRopCallerCheck : 1;                     // 0x754
      ULONG AuditRopCallerCheck : 1;                      // 0x754
      ULONG EnableRopSimExec : 1;                         // 0x754
      ULONG AuditRopSimExec : 1;                          // 0x754
      ULONG EnableImportAddressFilter : 1;                // 0x754
      ULONG AuditImportAddressFilter : 1;                 // 0x754
      ULONG DisablePageCombine : 1;                       // 0x754
      ULONG SpeculativeStoreBypassDisable : 1;            // 0x754
      ULONG CetUserShadowStacks : 1;                      // 0x754
      ULONG AuditCetUserShadowStacks : 1;                 // 0x754
      ULONG AuditCetUserShadowStacksLogged : 1;           // 0x754
      ULONG UserCetSetContextIpValidation : 1;            // 0x754
      ULONG AuditUserCetSetContextIpValidation : 1;       // 0x754
      ULONG AuditUserCetSetContextIpValidationLogged : 1; // 0x754
      ULONG CetUserShadowStacksStrictMode : 1;            // 0x754
      ULONG BlockNonCetBinaries : 1;                      // 0x754
      ULONG BlockNonCetBinariesNonEhcont : 1;             // 0x754
      ULONG AuditBlockNonCetBinaries : 1;                 // 0x754
      ULONG AuditBlockNonCetBinariesLogged : 1;           // 0x754
      ULONG XtendedControlFlowGuard_Deprecated : 1;       // 0x754
      ULONG AuditXtendedControlFlowGuard_Deprecated : 1;  // 0x754
      ULONG PointerAuthUserIp : 1;                        // 0x754
      ULONG AuditPointerAuthUserIp : 1;                   // 0x754
      ULONG AuditPointerAuthUserIpLogged : 1;             // 0x754
      ULONG CetDynamicApisOutOfProcOnly : 1;              // 0x754
      ULONG UserCetSetContextIpValidationRelaxedMode : 1; // 0x754
    } MitigationFlags2Values;                             // 0x754
  };
  VOID *PartitionObject;                                 // 0x758
  ULONGLONG SecurityDomain;                              // 0x760
  ULONGLONG ParentSecurityDomain;                        // 0x768
  VOID *CoverageSamplerContext;                          // 0x770
  VOID *MmHotPatchContext;                               // 0x778
  struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree; // 0x780
  struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock; // 0x788
  struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
      DynamicEnforcedCetCompatibleRanges;                // 0x790
  ULONG DisabledComponentFlags;                          // 0x7a0
  volatile LONG PageCombineSequence;                     // 0x7a4
  struct _EX_PUSH_LOCK EnableOptionalXStateFeaturesLock; // 0x7a8
  ULONG *volatile PathRedirectionHashes;                 // 0x7b0
  struct _PS_SYSCALL_PROVIDER *SyscallProvider;          // 0x7b8
  struct _LIST_ENTRY SyscallProviderProcessLinks;        // 0x7c0
  struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
      SyscallProviderDispatchContext; // 0x7d0
  union {
    ULONG MitigationFlags3; // 0x7d8
    struct {
      ULONG RestrictCoreSharing : 1;           // 0x7d8
      ULONG DisallowFsctlSystemCalls : 1;      // 0x7d8
      ULONG AuditDisallowFsctlSystemCalls : 1; // 0x7d8
      ULONG MitigationFlags3Spare : 29;        // 0x7d8
    } MitigationFlags3Values;                  // 0x7d8
  };
  union {
    ULONG Flags4; // 0x7dc
    struct {
      ULONG ThreadWasActive : 1;       // 0x7dc
      ULONG MinimalTerminate : 1;      // 0x7dc
      ULONG ImageExpansionDisable : 1; // 0x7dc
      ULONG SessionFirstProcess : 1;   // 0x7dc
    };
  };
  union {
    ULONG SyscallUsage; // 0x7e0
    struct {
      ULONG SystemModuleInformation : 1;           // 0x7e0
      ULONG SystemModuleInformationEx : 1;         // 0x7e0
      ULONG SystemLocksInformation : 1;            // 0x7e0
      ULONG SystemStackTraceInformation : 1;       // 0x7e0
      ULONG SystemHandleInformation : 1;           // 0x7e0
      ULONG SystemExtendedHandleInformation : 1;   // 0x7e0
      ULONG SystemObjectInformation : 1;           // 0x7e0
      ULONG SystemBigPoolInformation : 1;          // 0x7e0
      ULONG SystemExtendedProcessInformation : 1;  // 0x7e0
      ULONG SystemSessionProcessInformation : 1;   // 0x7e0
      ULONG SystemMemoryTopologyInformation : 1;   // 0x7e0
      ULONG SystemMemoryChannelInformation : 1;    // 0x7e0
      ULONG SystemUnused : 1;                      // 0x7e0
      ULONG SystemPlatformBinaryInformation : 1;   // 0x7e0
      ULONG SystemFirmwareTableInformation : 1;    // 0x7e0
      ULONG SystemBootMetadataInformation : 1;     // 0x7e0
      ULONG SystemWheaIpmiHardwareInformation : 1; // 0x7e0
      ULONG SystemSuperfetchPrefetch : 1;          // 0x7e0
      ULONG SystemSuperfetchPfnQuery : 1;          // 0x7e0
      ULONG SystemSuperfetchPrivSourceQuery : 1;   // 0x7e0
      ULONG SystemSuperfetchMemoryListQuery : 1;   // 0x7e0
      ULONG SystemSuperfetchMemoryRangesQuery : 1; // 0x7e0
      ULONG SystemSuperfetchPfnSetPriority : 1;    // 0x7e0
      ULONG SystemSuperfetchMovePages : 1;         // 0x7e0
      ULONG SystemSuperfetchPfnSetPageHeat : 1;    // 0x7e0
      ULONG SysDbgGetTriageDump : 1;               // 0x7e0
      ULONG SysDbgGetLiveKernelDump : 1;           // 0x7e0
      ULONG SyscallUsageValuesSpare : 5;           // 0x7e0
    } SyscallUsageValues;                          // 0x7e0
  };
  LONG SupervisorDeviceAsid;                         // 0x7e4
  VOID *SupervisorSvmData;                           // 0x7e8
  struct _PROCESS_NETWORK_COUNTERS *NetworkCounters; // 0x7f0
  union _PROCESS_EXECUTION Execution;                // 0x7f8
  VOID *ThreadIndexTable;                            // 0x800
};