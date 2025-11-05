#pragma once

#ifndef _INTELMACHINE

#include <cstdint>
#include <ia32-doc/ia32.hpp>

#pragma warning(push)
#pragma warning(disable: 4201)

enum class tlb_control_t : std::uint32_t
{
	do_not_flush = 0,
	flush_entire_tlb = 1, // should only be used on legacy hardware
	flush_guest_tlb_entries = 3,
	flush_guest_non_global_tlb_entries = 7,
};
union GuestInterruptStatus
{
	std::uint64_t data;
	struct
	{
		std::uint64_t interructShadow : 1;
		std::uint64_t guestInterruptMask : 1;
		std::uint64_t reservedBits : 62;
	} fields;
};
union VIntr
{
	std::uint64_t data;
	struct
	{
		std::uint8_t vipr;
		std::uint8_t virq : 1;
		std::uint8_t vgif : 1;
		std::uint8_t reservedBit : 1;
		std::uint8_t vnmi : 1;
		std::uint8_t vnmiMask : 1;
		std::uint8_t reservedBits1 : 3;
		std::uint8_t vIntrPrio : 4;
		std::uint8_t vIgnTpr : 1;
		std::uint8_t reservedBits2 : 3;
		std::uint8_t vIntrMasking : 1;
		std::uint8_t enableGIFForGuest : 1;
		std::uint8_t vNmiEnable : 1;
		std::uint8_t reservedBits3 : 3;
		std::uint8_t enableX2AVIC : 1;
		std::uint8_t enableAVIC : 1;
		std::uint8_t vIntrVector;
		std::uint8_t reservedBits4[3];
	} fields;
};
union SVMExtendFeatureBits1
{
	std::uint64_t data;
	struct
	{
		std::uint8_t enableNestedPage : 1;
		std::uint8_t enableSecureEncrypted : 1;
		std::uint8_t enableSecureEncryptedState : 1;
		std::uint8_t guestModeExecuteTrap : 1;
		std::uint8_t enableSSSCheck : 1;
		std::uint8_t virtualTransparentTrap : 1;
		std::uint8_t enableReadonlyGuestPage : 1;
		std::uint8_t invlpgbTlbsynAsUd : 1;
		std::uint8_t reservedBits[7];
	} fields;
};

union SVMExtendFeatureBits2
{
	std::uint64_t data;
	struct
	{
		std::uint64_t enableLBRVirtualcation : 1;
		std::uint64_t enableVirtualizedVmsaveVmload : 1;
		std::uint64_t reservedBits : 62;
	} fields;
};

union ApicBar
{
	std::uint64_t data;
	struct
	{
		std::uint64_t apicBar : 52;
		std::uint64_t reservedBits : 12;
	} fields;
};

union EventInj
{
	std::uint64_t flags;
	struct
	{
		std::uint64_t vector : 8;
		std::uint64_t type : 3;
		std::uint64_t ev : 1;
		std::uint64_t resvd1 : 19;
		std::uint64_t vaild : 1;
		std::uint64_t errorcode : 32;
	} fields;
};

union vmcb_clean_t
{
	std::uint64_t flags;

	struct
	{
		std::uint64_t i : 1;
		std::uint64_t iopm : 1;
		std::uint64_t asid : 1;
		std::uint64_t tpr : 1;
		std::uint64_t nested_paging : 1;
		std::uint64_t cr : 1;
		std::uint64_t dr : 1;
		std::uint64_t dt : 1;
		std::uint64_t seg : 1;
		std::uint64_t cr2 : 1;
		std::uint64_t lbr : 1;
		std::uint64_t avic : 1;
		std::uint64_t cet : 1;
		std::uint64_t reserved :51;
	};
};

struct vmcb_control_area_t
{
	std::uint16_t intercept_readCRX;
	std::uint16_t intrecept_writeCRX;
	std::uint16_t intercept_readDRX;
	std::uint16_t intrecept_writeDRX;
	std::uint32_t intercept_exceptionX;
	std::uint32_t intercept_opcodes1;
	std::uint32_t intercept_opcodes2;
	std::uint8_t reserved1[0x03c-0x014];
	std::uint16_t pause_filter_theshold;
	std::uint16_t pause_filter_count;
	std::uint64_t iopm_basePA;
	std::uint64_t msrpm_basePA;
	std::uint64_t tsc_offset;
	std::uint32_t guest_asID;
	tlb_control_t tlb_control;
	VIntr vintr;
	GuestInterruptStatus guest_interrupt_status;
	std::uint64_t vmexit_reason;
	std::uint64_t first_exit_info;
	std::uint64_t second_exit_info;
	std::uint64_t exit_int_info;
	SVMExtendFeatureBits1 extend_features1;
	ApicBar apic_bar;
	std::uint64_t physicalAddressGHCB;
	EventInj eventInj;
	cr3 nested_cr3;
	SVMExtendFeatureBits2 extend_features2;
	vmcb_clean_t clean;
	std::uint64_t next_rip;
	std::uint8_t NumOfBytesFetched;            // +0x0d0
	std::uint8_t GuestInstructionBytes[15];    // +0x0d1
	std::uint64_t AvicApicBackingPagePointer;  // +0x0e0
	std::uint64_t Reserved2;                   // +0x0e8
	std::uint64_t AvicLogicalTablePointer;     // +0x0f0
	std::uint64_t AvicPhysicalTablePointer;    // +0x0f8
	std::uint64_t Reserved3;                   // +0x100
	std::uint64_t VmcbSaveStatePointer;        // +0x108
	std::uint8_t Reserved4[0x400 - 0x110];     // +0x110
};
static_assert(sizeof(vmcb_control_area_t) == 0x400, "vmcb_control_area_t size mismatch");

struct vmcb_state_save_t
{
	std::uint8_t pad_one[0x150];
    std::uint64_t cr3;
    std::uint8_t pad_five[0x20];
    std::uint64_t rip;
    std::uint8_t pad_six[0x58];
    std::uint64_t rsp;
    std::uint8_t pad_seven[0x18];
    std::uint64_t rax;
};

struct vmcb_t
{
	vmcb_control_area_t control;
	vmcb_state_save_t save_state;
};

union npf_exit_info_1
{
	std::uint64_t flags;

	struct
	{
		std::uint64_t present : 1;
		std::uint64_t write_access : 1;
		std::uint64_t user_access : 1;
		std::uint64_t npte_reserved_set : 1;
		std::uint64_t execute_access : 1;
		std::uint64_t reserved_one : 1;
		std::uint64_t shadow_stack_access : 1;
		std::uint64_t reserved_two : 25;
		std::uint64_t final_gpa_translation : 1;
		std::uint64_t gpt_translation : 1;
		std::uint64_t reserved_three : 3;
		std::uint64_t supervisor_shadow_stack : 1;
		std::uint64_t reserved_four : 26;
	};
};

#pragma warning(pop)

#define SVM_EXIT_REASON_PHYSICAL_NMI 0x61
#define SVM_EXIT_REASON_CPUID 0x72
#define SVM_EXIT_REASON_PAUSE 0x77
#define SVM_EXIT_SMI   0x062
#define SVM_EXIT_REASON_NPF 0x400

#endif
