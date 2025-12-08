// 0x1c8 bytes (sizeof)
struct _KPROCESS {
  struct _DISPATCHER_HEADER Header;              // 0x0
  struct _LIST_ENTRY ProfileListHead;            // 0x18
  ULONGLONG DirectoryTableBase;                  // 0x28
  struct _LIST_ENTRY ThreadListHead;             // 0x30
  ULONG ProcessLock;                             // 0x40
  ULONG ProcessTimerDelay;                       // 0x44
  ULONGLONG DeepFreezeStartTime;                 // 0x48
  struct _KAFFINITY_EX *Affinity;                // 0x50
  struct _KAB_UM_PROCESS_CONTEXT AutoBoostState; // 0x58
  struct _LIST_ENTRY ReadyListHead;              // 0x68
  struct _SINGLE_LIST_ENTRY SwapListEntry;       // 0x78
  struct _KAFFINITY_EX *ActiveProcessors;        // 0x80
  union {
    struct {
      ULONG AutoAlignment : 1;         // 0x88
      ULONG DisableBoost : 1;          // 0x88
      ULONG DisableQuantum : 1;        // 0x88
      ULONG DeepFreeze : 1;            // 0x88
      ULONG TimerVirtualization : 1;   // 0x88
      ULONG CheckStackExtents : 1;     // 0x88
      ULONG CacheIsolationEnabled : 1; // 0x88
      ULONG PpmPolicy : 4;             // 0x88
      ULONG VaSpaceDeleted : 1;        // 0x88
      ULONG MultiGroup : 1;            // 0x88
      ULONG ForegroundProcess : 1;     // 0x88
      ULONG ReservedFlags : 18;        // 0x88
    };
    volatile LONG ProcessFlags; // 0x88
  };
  ULONG Spare0c;                        // 0x8c
  CHAR BasePriority;                    // 0x90
  CHAR QuantumReset;                    // 0x91
  CHAR Visited;                         // 0x92
  union _KEXECUTE_OPTIONS Flags;        // 0x93
  struct _KGROUP_MASK ActiveGroupsMask; // 0x98
  ULONGLONG ActiveGroupPadding[2];      // 0xa8
  struct _KI_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK
      *IdealProcessorAssignmentBlock;         // 0xb8
  ULONGLONG Padding[8];                       // 0xc0
  ULONG Spare0d;                              // 0x100
  USHORT IdealGlobalNode;                     // 0x104
  USHORT Spare1;                              // 0x106
  unionvolatile _KSTACK_COUNT StackCount;     // 0x108
  struct _LIST_ENTRY ProcessListEntry;        // 0x110
  ULONGLONG CycleTime;                        // 0x120
  ULONGLONG ContextSwitches;                  // 0x128
  struct _KSCHEDULING_GROUP *SchedulingGroup; // 0x130
  ULONGLONG KernelTime;                       // 0x138
  ULONGLONG UserTime;                         // 0x140
  ULONGLONG ReadyTime;                        // 0x148
  ULONG FreezeCount;                          // 0x150
  ULONG Spare4;                               // 0x154
  ULONGLONG UserDirectoryTableBase;           // 0x158
  UCHAR AddressPolicy;                        // 0x160
  UCHAR Spare2[7];                            // 0x161
  VOID *InstrumentationCallback;              // 0x168
  union {
    ULONGLONG SecureHandle; // 0x170
    struct {
      ULONGLONG SecureProcess : 1;                         // 0x170
      ULONGLONG TrustedApp : 1;                            // 0x170
    } Flags;                                               // 0x170
  } SecureState;                                           // 0x170
  ULONGLONG KernelWaitTime;                                // 0x178
  ULONGLONG UserWaitTime;                                  // 0x180
  ULONGLONG LastRebalanceQpc;                              // 0x188
  VOID *PerProcessorCycleTimes;                            // 0x190
  ULONGLONG ExtendedFeatureDisableMask;                    // 0x198
  USHORT PrimaryGroup;                                     // 0x1a0
  USHORT Spare3[3];                                        // 0x1a2
  VOID *UserCetLogging;                                    // 0x1a8
  struct _LIST_ENTRY CpuPartitionList;                     // 0x1b0
  struct _KPROCESS_AVAILABLE_CPU_STATE *AvailableCpuState; // 0x1c0
};