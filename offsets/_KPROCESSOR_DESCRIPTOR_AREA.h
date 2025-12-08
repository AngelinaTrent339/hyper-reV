// 0x5000 bytes (sizeof)
struct _KPROCESSOR_DESCRIPTOR_AREA {
  union _KIDTENTRY64 Idt[256];                  // 0x0
  struct _KTSS64 Tss;                           // 0x1000
  ULONGLONG TssSpare;                           // 0x1068
  struct _KPCR *KernelGsBase;                   // 0x1070
  VOID *IdleStack;                              // 0x1078
  UCHAR TssPad[3888];                           // 0x1080
  UCHAR GdtPadTemp[4096];                       // 0x1fb0
  union _KGDTENTRY64 Gdt[5];                    // 0x2fb0
  struct _KLDTENTRY GdtCmTebDescriptor;         // 0x3000
  UCHAR GdtEndPadding[4088];                    // 0x3008
  struct _KTRANSITION_STACK TransitionStack[8]; // 0x4000
};