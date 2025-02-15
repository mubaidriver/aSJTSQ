#pragma once

#ifndef _VMCS_H
#define _VMCS_H

//ջ�����������ڴ���ʵ�Ч��
//��x64�ܹ��У�ջ����16�ֽڶ����
#define StackAlignment(x) ((x) & ~0xF)

#define _MINIMAL


/* VMCS Encordings */
enum
{
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTERRUPT_NOTIFICATION_VECTOR = 0x00000002,
    EPTP_INDEX = 0x00000004,
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    GUEST_INTERRUPT_STATUS = 0x00000810,
    GUEST_PML_INDEX = 0x00000812,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A_ADDRESS = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B_ADDRESS = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP_ADDRESS = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    VMCS_EXECUTIVE_POINTER = 0x0000200c,
    PML_ADDRESS = 0x0000200e,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    APIC_ACCESS_ADDRESS = 0x00002014,
    POSTED_INTERRUPT_DESCRIPTOR_ADDRESS = 0x00002016,
    VM_FUNCTION_CONTROLS = 0x00002018,
    EPT_POINTER = 0x0000201a,
    EOI_EXIT_BITMAP_0 = 0x0000201c,
    EOI_EXIT_BITMAP_1 = 0x0000201e,
    EOI_EXIT_BITMAP_2 = 0x00002020,
    EOI_EXIT_BITMAP_3 = 0x00002022,
    EPTP_LIST_ADDRESS = 0x00002024,
    VMREAD_BITMAP_ADDRESS = 0x00002026,
    VMWRITE_BITMAP_ADDRESS = 0x00002028,
    VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS = 0x0000202a,
    XSS_EXITING_BITMAP = 0x0000202c,
    ENCLS_EXITING_BITMAP = 0x0000202e,
    SUB_PAGE_PERMISSION_TABLE_POINTER = 0x00002030,
    TSC_MULTIPLIER = 0x00002032,
    ENCLV_EXITING_BITMAP = 0x00002036,
    GUEST_PHYSICAL_ADDRESS = 0x00002400,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_DEBUG_CONTROL = 0x00002802,
    GUEST_IA32_DEBUG_CTL_HIGH = 0x00002803,
    GUEST_PAT = 0x00002804,
    GUEST_EFER = 0x00002806,
    GUEST_PERF_GLOBAL_CONTROL = 0x00002808,
    GUEST_PDPTE0 = 0x0000280a,
    GUEST_PDPTE1 = 0x0000280c,
    GUEST_PDPTE2 = 0x0000280e,
    GUEST_PDPTE3 = 0x00002810,
    GUEST_BNDCFGS = 0x00002812,
    GUEST_RTIT_CTL = 0x00002814,
    GUEST_PKRS = 0x00002816,
    HOST_PAT = 0x00002c00,
    HOST_EFER = 0x00002c02,
    HOST_PERF_GLOBAL_CTRL = 0x00002c04,
    HOST_PKRS = 0x00002c06,
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTERRUPTION_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LENGTH = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_PROCESSOR_BASED_VM_EXEC_CONTROL = 0x0000401e,
    CONTROL_PLE_GAP = 0x00004020,
    CONTROL_PLE_WINDOW = 0x00004022,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTERRUPTION_INFORMATION = 0x00004404,
    VM_EXIT_INTERRUPTION_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LENGTH = 0x0000440c,
    VM_EXIT_INSTRUCTION_INFORMATION = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_ACCESS_RIGHTS = 0x00004814,
    GUEST_CS_ACCESS_RIGHTS = 0x00004816,
    GUEST_SS_ACCESS_RIGHTS = 0x00004818,
    GUEST_DS_ACCESS_RIGHTS = 0x0000481a,
    GUEST_FS_ACCESS_RIGHTS = 0x0000481c,
    GUEST_GS_ACCESS_RIGHTS = 0x0000481e,
    GUEST_LDTR_ACCESS_RIGHTS = 0x00004820,
    GUEST_TR_ACCESS_RIGHTS = 0x00004822,
    GUEST_INTERRUPTIBILITY_STATE = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SM_BASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482a,
    GUEST_VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    IO_RCX = 0x00006402,
    IO_RSI = 0x00006404,
    IO_RDI = 0x00006406,
    IO_RIP = 0x00006408,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DEBUG_EXCEPTION = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    GUEST_S_CET = 0x00006828,
    GUEST_SSP = 0x0000682a,
    GUEST_INTERRUPT_SSP_TABLE_ADDR = 0x0000682c,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
    Host_IA32_S_CET = 0x00006c18,
    HOST_SSP = 0x00006c1a,
    Host_IA32_INTERRUPT_SSP_TABLE_ADDR = 0x00006c1c,
};

union __vmx_secondary_processor_based_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 virtualize_apic_accesses : 1;  //0
        unsigned __int64 enable_ept : 1;  //1
        unsigned __int64 descriptor_table_exiting : 1;  //2
        unsigned __int64 enable_rdtscp : 1;  //3
        unsigned __int64 virtualize_x2apic_mode : 1;  //4
        unsigned __int64 enable_vpid : 1;  //5
        unsigned __int64 wbinvd_exiting : 1;  //6
        unsigned __int64 unrestricted_guest : 1;  //7
        unsigned __int64 apic_register_virtualization : 1;  //8
        unsigned __int64 virtual_interrupt_delivery : 1;  //9
        unsigned __int64 pause_loop_exiting : 1;  //10
        unsigned __int64 rdrand_exiting : 1;  //11
        unsigned __int64 enable_invpcid : 1;  //12
        unsigned __int64 enable_vmfunc : 1;  //13
        unsigned __int64 vmcs_shadowing : 1;  //14
        unsigned __int64 enable_encls_exiting : 1;  //15
        unsigned __int64 rdseed_exiting : 1;  //16
        unsigned __int64 enable_pml : 1;  //17
        unsigned __int64 ept_violation : 1;  //18
        unsigned __int64 conceal_vmx_from_pt : 1;  //19
        unsigned __int64 enable_xsaves_xrstors : 1;  //20
        unsigned __int64 reserved_0 : 1;  //21
        unsigned __int64 mode_based_execute_control_ept : 1;  //22
        unsigned __int64 sub_page_write_permission_for_ept : 1;  //23
        unsigned __int64 intel_pt_uses_guest_physical_address : 1;  //24
        unsigned __int64 use_tsc_scaling : 1;  //25
        unsigned __int64 enable_user_wait_and_pause : 1;  //26
        unsigned __int64 enable_pconfig : 1;  //27
        unsigned __int64 enable_enclv_exiting : 1;  //28
    };
};

union __vmx_primary_processor_based_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2;  //1:0
        unsigned __int64 interrupt_window_exiting : 1;  //2
        unsigned __int64 use_tsc_offsetting : 1;  //3
        unsigned __int64 reserved_1 : 3;  //6:4
        unsigned __int64 hlt_exiting : 1;  //7
        unsigned __int64 reserved_2 : 1;  //8
        unsigned __int64 invlpg_exiting : 1;  //9
        unsigned __int64 mwait_exiting : 1;  //10
        unsigned __int64 rdpmc_exiting : 1;  //11
        unsigned __int64 rdtsc_exiting : 1;  //12
        unsigned __int64 reserved_3 : 2;  //14:13
        unsigned __int64 cr3_load_exiting : 1;  //15
        unsigned __int64 cr3_store_exiting : 1;  //16
        unsigned __int64 activate_tertiary_controls : 1;  //17
        unsigned __int64 reserved_4 : 1;  //18
        unsigned __int64 cr8_load_exiting : 1;  //19
        unsigned __int64 cr8_store_exiting : 1;  //20
        unsigned __int64 use_tpr_shadow : 1;  //21
        unsigned __int64 nmi_window_exiting : 1;  //22
        unsigned __int64 mov_dr_exiting : 1;  //23
        unsigned __int64 unconditional_io_exiting : 1;  //24
        unsigned __int64 use_io_bitmaps : 1;  //25
        unsigned __int64 reserved_5 : 1;  //26
        unsigned __int64 monitor_trap_flag : 1;  //27
        unsigned __int64 use_msr_bitmaps : 1;  //28
        unsigned __int64 monitor_exiting : 1;  //29
        unsigned __int64 pause_exiting : 1;  //30
        unsigned __int64 active_secondary_controls : 1;  //31
    };
};

union __vmx_pinbased_control_msr
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 external_interrupt_exiting : 1;  //0
        unsigned __int64 reserved_0 : 2;  //2:1
        unsigned __int64 nmi_exiting : 1;  //3
        unsigned __int64 reserved_1 : 1;  //4
        unsigned __int64 virtual_nmis : 1;  //5
        unsigned __int64 activate_vmxpreemption_timer : 1;  //6
        unsigned __int64 process_posted_interrupts : 1;  //7
    };
};

union __vmx_true_control_settings
{
    unsigned __int64 all;
    struct
    {
        unsigned __int32 allowed_0_settings;
        unsigned __int32 allowed_1_settings;
    };
};

union __interrupt_command_register
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 vector : 8;
        unsigned __int64 delivery_mode : 3;
        unsigned __int64 destination_mode : 1;
        unsigned __int64 delivery_status : 1;
        unsigned __int64 reserved_0 : 1;
        unsigned __int64 level : 1;
        unsigned __int64 trigger_mode : 1;
        unsigned __int64 reserved_1 : 2;
        unsigned __int64 destination_short : 2;
        unsigned __int64 reserved_3 : 35;
        unsigned __int64 destination : 8;
    };
};

union __vmx_entry_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2;  //1:0
        unsigned __int64 load_dbg_controls : 1;  //2
        unsigned __int64 reserved_1 : 6;  //8:3
        unsigned __int64 ia32e_mode_guest : 1;  //9
        unsigned __int64 entry_to_smm : 1;  //10
        unsigned __int64 deactivate_dual_monitor_treament : 1;  //11
        unsigned __int64 reserved_2 : 1;  //12
        unsigned __int64 load_ia32_perf_global_control : 1;  //13
        unsigned __int64 load_ia32_pat : 1;  //14
        unsigned __int64 load_ia32_efer : 1;  //15
        unsigned __int64 load_ia32_bndcfgs : 1;  //16
        unsigned __int64 conceal_vmx_from_pt : 1;  //17
        unsigned __int64 load_ia32_rtit_ctl : 1;  //18
        unsigned __int64 reserved_3 : 1;  //19
        unsigned __int64 load_cet_state : 1;  //20
        unsigned __int64 load_guest_ia32_lbr_ctl : 1;  //21
        unsigned __int64 load_pkrs : 1;  //22
    };
};

union __vmx_exit_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2;  //1:0
        unsigned __int64 save_dbg_controls : 1;  //2
        unsigned __int64 reserved_1 : 6;  //8:3
        unsigned __int64 host_address_space_size : 1;  //9
        unsigned __int64 reserved_2 : 2;  //11:10
        unsigned __int64 load_ia32_perf_global_control : 1;  //12
        unsigned __int64 reserved_3 : 2;  //14:13
        unsigned __int64 acknowledge_interrupt_on_exit : 1;  //15
        unsigned __int64 reserved_4 : 2;  //17:16
        unsigned __int64 save_ia32_pat : 1;  //18
        unsigned __int64 load_ia32_pat : 1;  //19
        unsigned __int64 save_ia32_efer : 1;  //20
        unsigned __int64 load_ia32_efer : 1;  //21
        unsigned __int64 save_vmx_preemption_timer_value : 1;  //22
        unsigned __int64 clear_ia32_bndcfgs : 1;  //23
        unsigned __int64 conceal_vmx_from_pt : 1;  //24
        unsigned __int64 clear_ia32_rtit_ctl : 1;  //25
        unsigned __int64 clear_ia32_lbr_ctl : 1;  //26
        unsigned __int64 reserved_5 : 1;  //27
        unsigned __int64 load_cet_state : 1;  //28
        unsigned __int64 load_pkrs : 1;  //29
        unsigned __int64 save_ia32_perf_global_ctl : 1;  //30
        unsigned __int64 activate_secondary_controls : 1;  //31
    };
};

union __vmx_pending_debug_exceptions
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 b0 : 1;
        unsigned __int64 b1 : 1;
        unsigned __int64 b2 : 1;
        unsigned __int64 b3 : 1;
        unsigned __int64 reserved1 : 8;
        unsigned __int64 enabled_bp : 1;
        unsigned __int64 reserved2 : 1;
        unsigned __int64 bs : 1;
        unsigned __int64 reserved3 : 1;
        unsigned __int64 rtm : 1;
        unsigned __int64 reserved4 : 47;
    };

};

union __vmx_interruptibility_state
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 blocking_by_sti : 1;
        unsigned __int64 blocking_by_mov_ss : 1;
        unsigned __int64 blocking_by_smi : 1;
        unsigned __int64 blocking_by_nmi : 1;
        unsigned __int64 enclave_interruption : 1;
        unsigned __int64 reserved : 27;
    };
};

void fill_vmcs(__vcpu* vcpu, void* guest_rsp);

#endif // !_VMCS_H
