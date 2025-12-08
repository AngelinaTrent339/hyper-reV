// 0x78 bytes (sizeof)
struct _KPROCESS_AVAILABLE_CPU_STATE {
  union _RTL_TICK_LOCK SequenceNumber;          // 0x0
  ULONGLONG CpuSetSequenceNumber;               // 0x8
  ULONGLONG ForceParkSequenceNumber;            // 0x10
  struct _KAFFINITY_EX *Affinity;               // 0x18
  struct _EX_PUSH_LOCK SubscriptionLock;        // 0x20
  struct _LIST_ENTRY SubscriptionList;          // 0x28
  struct _KI_AVAILABLE_CPUS_WORK_ITEM WorkItem; // 0x38
};