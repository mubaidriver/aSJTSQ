#include "Driver.h"
#include "poolmanager.h"
#include "Globals.h"
#include "mtrr.h"
#include "EPT.h"
#include "hypervisor_routines.h"
#include "vmcs.h"
#include "interrupt.h"
#include "ntapi.h"
#include "AsmCallset.h"

__pseudo_descriptor64 g_gdtr = { 0 };
__pseudo_descriptor64 g_idtr = { 0 };
unsigned __int64 g_guest_cr0;
unsigned __int64 g_guest_cr3;
unsigned __int64 g_guest_cr4;
__vmm_context g_vmm_context;
uint16_t guest_vpid = 1;
int eptWatchListSize;
int eptWatchListPos;
volatile long eptWatchList_lock = 0;

EPTWatchEntry eptWatchList[EPTWATCHLISTSIZE];



PFN_PSGETNEXTPROCESS PsGetNextProcess;


namespace ethread_offset
{
    size_t Tcb;
    size_t CrossThreadFlags;
    size_t Cid;
    size_t RundownProtect;
}

namespace hv
{
    // selectors for the host GDT
    // host��gdtѡ����
    segment_selector host_cs_selector = { 0, 0, 1 };
    segment_selector host_tr_selector = { 0, 0, 2 };
    //��host�������ַӳ����pml4[255]��
    uint64_t host_physical_memory_pml4_idx = 255;

    // directly access physical memory by using [base + offset]
    // ָʾ��Ч��4����ҳ��pml4[255]��ʼ
    uint8_t* host_physical_memory_base = reinterpret_cast<uint8_t*>((uint64_t)255 << (9 + 9 + 9 + 12));
    
    hypervisor ghv;


    ia32_vmx_procbased_ctls_register read_ctrl_proc_based() {
        ia32_vmx_procbased_ctls_register value;
        value.flags = vmread(PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL);
        return value;
    }

    void write_ctrl_proc_based(ia32_vmx_procbased_ctls_register const value) {
        vmwrite(PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL, value.flags);
    }

    //����host��idt��gdt
    void prepare_external_structures(__vcpu* const vcpu) {
        memset(&vcpu->msr_bitmap, 0, sizeof(vcpu->msr_bitmap));
        //enable_exit_for_msr_read(vcpu->msr_bitmap, IA32_FEATURE_CONTROL, true);

        //enable_mtrr_exiting(vcpu);

        // we don't care about anything that's in the TSS
        memset(&vcpu->host_tss, 0, sizeof(vcpu->host_tss));

        prepare_host_idt(vcpu->host_idt);
        prepare_host_gdt(vcpu->host_gdt, &vcpu->host_tss);

        //prepare_ept(vcpu->ept);
    }

    // inject an NMI into the guest
    void inject_nmi() {
        //vmentry_interrupt_information interrupt_info;
        //interrupt_info.flags = 0;
        //interrupt_info.vector = nmi;
        //interrupt_info.interruption_type = non_maskable_interrupt;
        //interrupt_info.deliver_error_code = 0;
        //interrupt_info.valid = 1;
        //vmwrite(VM_ENTRY_INTERRUPTION_INFO_FIELD, interrupt_info.flags);
        inject_interruption(EXCEPTION_VECTOR_NMII, INTERRUPT_TYPE_NMI, 0, false);
    }

    cr0 read_effective_guest_cr0() {
        // TODO: cache this value
        auto const mask = vmread(CR0_GUEST_HOST_MASK);

        // bits set to 1 in the mask are read from CR0, otherwise from the shadow
        cr0 cr0;
        cr0.flags = (vmread(CR0_READ_SHADOW) & mask) | (vmread(GUEST_CR0) & ~mask);

        return cr0;
    }

    cr4 read_effective_guest_cr4() {
        // TODO: cache this value
        auto const mask = vmread(CR4_GUEST_HOST_MASK);

        // bits set to 1 in the mask are read from CR4, otherwise from the shadow
        cr4 cr4;
        cr4.flags = (vmread(CR4_READ_SHADOW) & mask) | (vmread(GUEST_CR4) & ~mask);

        return cr4;
    }

    // directly map physical memory into the host page tables
    // ����ֻӳ��512GB���ڴ�
    void map_physical_memory(host_page_tables& pt) {
        auto& pml4e = pt.pml4[host_physical_memory_pml4_idx];
        pml4e.flags = 0;
        pml4e.present = 1;
        pml4e.write = 1;
        pml4e.supervisor = 0;
        pml4e.page_level_write_through = 0;
        pml4e.page_level_cache_disable = 0;
        pml4e.accessed = 0;
        pml4e.execute_disable = 0;
        pml4e.page_frame_number = MmGetPhysicalAddress(&pt.phys_pdpt).QuadPart >> 12;

        for (uint64_t i = 0; i < HOST_PHYSICAL_MEMORY_PD_COUNT; ++i) {
            auto& pdpte = pt.phys_pdpt[i];
            pdpte.flags = 0;
            pdpte.present = 1;
            pdpte.write = 1;
            pdpte.supervisor = 0;
            pdpte.page_level_write_through = 0;
            pdpte.page_level_cache_disable = 0;
            pdpte.accessed = 0;
            pdpte.execute_disable = 0;
            pdpte.page_frame_number = MmGetPhysicalAddress(&pt.phys_pds[i]).QuadPart >> 12;

            for (uint64_t j = 0; j < 512; ++j) {
                auto& pde = pt.phys_pds[i][j];
                pde.flags = 0;
                pde.present = 1;
                pde.write = 1;
                pde.supervisor = 0;
                pde.page_level_write_through = 0;
                pde.page_level_cache_disable = 0;
                pde.accessed = 0;
                pde.dirty = 0;
                pde.large_page = 1;  //����2mb ��ҳ��
                pde.global = 0;
                pde.pat = 0;
                pde.execute_disable = 0;
                pde.page_frame_number = (i << 9) + j; //����pfn ҳ֡�Ŵ�0��ʼ
            }
        }
    }

    void map_physical_memory2(host_page_tables& pt) {
        auto& pml4e = pt.pml4[host_physical_memory_pml4_idx];
        pml4e.flags = 0;
        pml4e.present = 1;
        pml4e.write = 1;
        pml4e.supervisor = 0;
        pml4e.page_level_write_through = 0;
        pml4e.page_level_cache_disable = 0;
        pml4e.accessed = 0;
        pml4e.execute_disable = 0;
        pml4e.page_frame_number = MmGetPhysicalAddress(&pt.phys_pdpt).QuadPart >> 12;


        pdpte_64 pdpte = { 0 };
        pdpte.present = 1;
        pdpte.write = 1;
        pdpte.supervisor = 0;
        pdpte.page_level_write_through = 0;
        pdpte.page_level_cache_disable = 0;
        pdpte.accessed = 0;
        pdpte.execute_disable = 0;
        __stosq((unsigned __int64*)&pt.phys_pdpt[0], pdpte.flags, HOST_PHYSICAL_MEMORY_PD_COUNT);

        for (uint64_t i = 0; i < HOST_PHYSICAL_MEMORY_PD_COUNT; ++i)
        {
            pt.phys_pdpt[i].page_frame_number = GET_PFN(MmGetPhysicalAddress(&pt.phys_pds[i]).QuadPart);
        }

        pde_2mb_64 pde = { 0 };
        pde.present = 1;
        pde.write = 1;
        pde.supervisor = 0;
        pde.page_level_write_through = 0;
        pde.page_level_cache_disable = 0;
        pde.accessed = 0;
        pde.dirty = 0;
        pde.large_page = 1;  //����2mb ��ҳ��
        pde.global = 0;
        pde.pat = 0;
        pde.execute_disable = 0;
        __stosq((unsigned __int64*)&pt.phys_pds[0], pde.flags, 512 * 512);

        for (uint64_t i = 0; i < HOST_PHYSICAL_MEMORY_PD_COUNT; ++i) {
            for (uint64_t j = 0; j < 512; ++j) {
                pt.phys_pds[i][j].page_frame_number = (i << 9) + j; //����pfn ҳ֡�Ŵ�0��ʼ
            }
        }
    }

    // initialize the host page tables
    // ��ʼ��hostҳ��
    void prepare_host_page_tables() {
        auto& pt = ghv.host_page_tables;
        memset(&pt, 0, sizeof(pt));

        map_physical_memory(pt);

        //�Ȼ��kernel system���̵�cr3��pml4�������ַ
        PHYSICAL_ADDRESS pml4_address;
        pml4_address.QuadPart = ghv.system_cr3.address_of_page_directory << 12;

        // kernel PML4 address
        // ��kernel pml4�����ַ�õ��������Ե�ַ
        // ��Ϊmemcpy��Щ�����ǲ��������ַ��
        auto const guest_pml4 = static_cast<pml4e_64*>(MmGetVirtualForPhysical(pml4_address));
        outDebug("guest_pml4: %p\n", guest_pml4->flags);

        // copy the top half of the System pml4 (a.k.a. the kernel address space)
        // ����system pml4 �ĺ�벿�֣��ֳ��ں˵�ַ�ռ䣩
        // ��256����39λ�õ�0x800000000000
        //outDebug("&guest_pml4[256]: %p\n", &guest_pml4[256]);
        memcpy(&pt.pml4[256], &guest_pml4[256], sizeof(pml4e_64) * 256);
    }

    bool load_vmcs_pointer(vmcs& vmcs_region) {
        ia32_vmx_basic_register vmx_basic;
        vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

        // 3.24.2
        vmcs_region.revision_id = vmx_basic.vmcs_revision_id;
        vmcs_region.shadow_vmcs_indicator = 0;

        auto vmcs_phys = MmGetPhysicalAddress(&vmcs_region).QuadPart;
        NT_ASSERT(vmcs_phys % 0x1000 == 0);

        if (!hv::vmx_vmclear(vmcs_phys)) {
            return false;
        }

        if (!hv::vmx_vmptrld(vmcs_phys)) {
            return false;
        }

        return true;
    }

    //��ȡguestͨ�üĴ���
    uint64_t read_guest_gpr(guest_context const* const ctx, uint64_t const gpr_idx)
    {
        if (gpr_idx == VMX_EXIT_QUALIFICATION_GENREG_RSP)
            return hv::vmread(GUEST_RSP);
        return ctx->gpr[gpr_idx];
    }

    //дguestͨ�üĴ���
    void write_guest_gpr(guest_context* const ctx, uint64_t const gpr_idx, uint64_t const value)
    {
        if (gpr_idx == VMX_EXIT_QUALIFICATION_GENREG_RSP)
            vmwrite(GUEST_RSP, value);
        else
            ctx->gpr[gpr_idx] = value;
    }

    vmx_interruptibility_state read_interruptibility_state()
    {
        vmx_interruptibility_state value;
        value.flags = static_cast<uint32_t>(vmread(GUEST_INTERRUPTIBILITY_STATE));
        return value;
    }

    void write_interruptibility_state(vmx_interruptibility_state const value)
    {
        hv::vmwrite(GUEST_INTERRUPTIBILITY_STATE, value.flags);
    }

    bool enter_vmx_operation(vmxon& vmxon_region)
    {
        ia32_vmx_basic_register vmx_basic;
        vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

        // 3.24.11.5
        vmxon_region.revision_id = vmx_basic.vmcs_revision_id;
        vmxon_region.must_be_zero = 0;

        auto vmxon_phys = MmGetPhysicalAddress(&vmxon_region).QuadPart;
        NT_ASSERT(vmxon_phys % 0x1000 == 0);

        // enter vmx operation
        if (!vmx_on(vmxon_phys)) {
            return false;
        }

        // 3.28.3.3.4
        invept_all_contexts_func();

        return true;
    }

    // read MTRR data into a single structure
    // ��ȡMTRR������Ϣ
    mtrr_data read_mtrr_data() {
        mtrr_data mtrrs;

        mtrrs.cap.flags = __readmsr(IA32_MTRR_CAPABILITIES);
        mtrrs.def_type.flags = __readmsr(IA32_MTRR_DEF_TYPE);
        mtrrs.var_count = 0;

        for (uint32_t i = 0; i < mtrrs.cap.variable_range_count; ++i) {
            ia32_mtrr_physmask_register mask;
            mask.flags = __readmsr(IA32_MTRR_PHYSMASK0 + i * 2);

            if (!mask.valid)
                continue;

            mtrrs.variable[mtrrs.var_count].mask = mask;
            mtrrs.variable[mtrrs.var_count].base.flags = __readmsr(IA32_MTRR_PHYSBASE0 + i * 2);

            ++mtrrs.var_count;
        }

        return mtrrs;
    }

    // calculate the MTRR memory type for a single page
    // ���㵥��ҳ��� MTRR �ڴ�����
    static uint8_t calc_mtrr_mem_type(mtrr_data const& mtrrs, uint64_t const pfn) {
        if (!mtrrs.def_type.mtrr_enable)
        {
            // MTRRs����������ζ�����е������ڴ涼������ΪUC
            return MEMORY_TYPE_UNCACHEABLE;
        }            

        // fixed range MTRRs
        // �̶���ΧMTRRs
        if (pfn < 0x100 && mtrrs.cap.fixed_range_supported && mtrrs.def_type.fixed_range_mtrr_enable)
        {
            // ���pfnС��256 �ҿ����˹̶���ΧMTRRs
            // �������ڴ���ΪUC����
            return MEMORY_TYPE_UNCACHEABLE;
        }

        uint8_t curr_mem_type = MEMORY_TYPE_INVALID;

        // variable-range MTRRs
        // �ɱ䷶ΧMTRRs
        for (uint32_t i = 0; i < mtrrs.var_count; ++i) {
            auto const base = mtrrs.variable[i].base.page_frame_number;
            auto const mask = mtrrs.variable[i].mask.page_frame_number;


            //Vol.3A[12.11.3]
            //��Χ�ڵ��κε�ַ��mask���� ��λ�� ����ʱ����������base��mask���� ��λ�� ����ʱ��ͬ��ֵ��
            if ((pfn & mask) == (base & mask)) {
                auto const type = static_cast<uint8_t>(mtrrs.variable[i].base.type);

                //�ж��Ƿ���UC���ͣ����������������
                if (type == MEMORY_TYPE_UNCACHEABLE)
                    return MEMORY_TYPE_UNCACHEABLE;

                // this works for WT and WB, which is the only other "defined" overlap scenario
                if (type < curr_mem_type)
                    curr_mem_type = type;
            }
        }

        // no MTRR covers the specified address
        //δ�� MTRR ӳ��ĵ�ַ��ΧӦ����ΪĬ������
        if (curr_mem_type == MEMORY_TYPE_INVALID)
            return mtrrs.def_type.default_memory_type;

        return curr_mem_type;
    }

    // calculate the MTRR memory type for the given physical memory range
    // ������������ڴ淶Χ�� MTRR �ڴ�����
    uint8_t calc_mtrr_mem_type(mtrr_data const& mtrrs, uint64_t address, uint64_t size) {
        // base address must be on atleast a 4KB boundary
        // ����ַ��������λ�� 4KB �߽���
        address &= ~0xFFFull;

        // minimum range size is 4KB
        // ��С��Χ��СΪ 4KB
        size = (size + 0xFFF) & ~0xFFFull;

        //�Ƚ����ʼ��Ϊ��Ч���ڴ�����
        uint8_t curr_mem_type = MEMORY_TYPE_INVALID;

        for (uint64_t curr = address; curr < address + size; curr += 0x1000) {
            auto const type = calc_mtrr_mem_type(mtrrs, curr >> 12/*�õ�pfn*/);

            if (type == MEMORY_TYPE_UNCACHEABLE)
                return type;

            // use the worse memory type between the two
            if (type < curr_mem_type)
                curr_mem_type = type;
        }

        if (curr_mem_type == MEMORY_TYPE_INVALID)
            return MEMORY_TYPE_UNCACHEABLE;

        return curr_mem_type;
    }

    // set the memory type in every EPT paging structure to the specified value
    // ��ÿ�� EPT ��ҳ�ṹ�е��ڴ���������Ϊָ��ֵ��ÿ�� EPT ��ҳ�ṹ�е��ڴ���������Ϊָ��ֵ
    void set_ept_memory_type(__ept_state& ept_state, uint8_t const memory_type)
    {
        for (size_t i = 0; i < EPT_PD_COUNT; ++i)
        {
            for (size_t j = 0; j < 512; ++j)
            {
                auto& pde = ept_state.ept_page_table->pml2[i][j];

                // 2MB large page
                // 2MB ��ҳ��
                if (pde.page_directory_entry.large_page)
                {
                    pde.page_directory_entry.memory_type = memory_type;
                }
                else
                {
                    // PDE ָ��һ�� PT
                    auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base + (pde.large_page.page_frame_number << 12));

                    // update the memory type for every PTE
                    // ����ÿ�� PTE ���ڴ�����
                    for (size_t k = 0; k < 512; ++k)
                        pt[k].memory_type = memory_type;
                }
            }
        }
    }

    // update the memory types in the EPT paging structures based on the MTRRs.
    // ���� MTRR ���� EPT ��ҳ�ṹ�е��ڴ����͡�
    // this function should only be called from root-mode during vmx-operation.
    // �˺���Ӧ���� vmx-operation �ڼ��host���á�
    void update_ept_memory_type(__ept_state& ept_state)
    {
        // TODO: completely virtualize the guest MTRRs
        // ��ȫ���⻯guest MTRR
        auto const mtrrs = read_mtrr_data();

        for (size_t i = 0; i < EPT_PD_COUNT; ++i) {
            for (size_t j = 0; j < 512; ++j) {
                auto& pde = ept_state.ept_page_table->pml2[i][j];

                // 2MB large page
                if (pde.page_directory_entry.large_page) {
                    // update the memory type for this PDE
                    pde.page_directory_entry.memory_type = calc_mtrr_mem_type(mtrrs,
                        pde.page_directory_entry.page_frame_number << 21, 0x1000 << 9);
                }
                // PDE points to a PT
                else {
                    auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base + (pde.large_page.page_frame_number << 12));

                    // update the memory type for every PTE
                    for (size_t k = 0; k < 512; ++k) {
                        pt[k].memory_type = calc_mtrr_mem_type(mtrrs, pt[k].page_frame_number << 12, 0x1000);
                    }
                }
            }
        }
    }

    // ��guest�����ַתΪguest�����ַ
    // �� GVA ת��Ϊ GPA, offset_to_next_page ����һҳ���ֽ���������ͨ�� GPA ��ȫ�������޸� GVA ���ֽ�������
    uint64_t gva2gpa(cr3 const guest_cr3, void* const gva, size_t* const offset_to_next_page) {
        if (offset_to_next_page)
            *offset_to_next_page = 0;

        pml4_virtual_address const vaddr = { gva };

        // guest PML4
        // �������ǽ����е������ַӳ������host pt.pml4[255]��ʼ�ĵط�
        // ��������Ҫ����GPA pml4_idx��host pml4[255]����ʼ
        // ��host pt.pml4[255]����ʼ
        auto const pml4 = reinterpret_cast<pml4e_64*>(host_physical_memory_base + (guest_cr3.address_of_page_directory << 12));
        auto const pml4e = pml4[vaddr.pml4_idx];

        //�жϸ�ҳ�Ƿ����
        //��P=1ָʾ�������ҳ���Ѽ��ص������ڴ���
        if (!pml4e.present)
            return 0;

        // guest PDPT
        // ��Ϊvm������Ե�ַ������host��˵���������ַ
        // ����������host����Ȼ�ǽ�gpa�ĵ�ַ�������Ե�ַ������
        // ��������Ҫ�����Ե�ַ��pml4_idx��pml4[255]����ʼ
        auto const pdpt = reinterpret_cast<pdpte_64*>(host_physical_memory_base + (pml4e.page_frame_number << 12));
        auto const pdpte = pdpt[vaddr.pdpt_idx];

        if (!pdpte.present)
            return 0;

        if (pdpte.large_page) {
            pdpte_1gb_64 pdpte_1gb;
            pdpte_1gb.flags = pdpte.flags;

            auto const offset = (vaddr.pd_idx << 21) + (vaddr.pt_idx << 12) + vaddr.offset;

            // 1GB
            if (offset_to_next_page)
                *offset_to_next_page = 0x40000000 - offset;

            return (pdpte_1gb.page_frame_number << 30) + offset;
        }

        // guest PD
        auto const pd = reinterpret_cast<pde_64*>(host_physical_memory_base + (pdpte.page_frame_number << 12));
        auto const pde = pd[vaddr.pd_idx];

        if (!pde.present)
            return 0;

        if (pde.large_page) {
            pde_2mb_64 pde_2mb;
            pde_2mb.flags = pde.flags;

            auto const offset = (vaddr.pt_idx << 12) + vaddr.offset;

            // 2MB page
            if (offset_to_next_page)
                *offset_to_next_page = 0x200000 - offset;

            return (pde_2mb.page_frame_number << 21) + offset;
        }

        // guest PT
        auto const pt = reinterpret_cast<pte_64*>(host_physical_memory_base + (pde.page_frame_number << 12));
        auto const pte = pt[vaddr.pt_idx];

        if (!pte.present)
            return 0;

        // 4KB page
        if (offset_to_next_page)
            *offset_to_next_page = 0x1000 - vaddr.offset;

        //(pte.page_frame_number << 12) 4KB����ҳ����ʼ��ַ + offset��õ�����������ַ
        return (pte.page_frame_number << 12) + vaddr.offset;
    }

    // translate a GVA to an HVA. offset_to_next_page is the number of bytes to
    // the next page (i.e. the number of bytes that can be safely accessed through
    // the HVA in order to modify the GVA.
    void* gva2hva(cr3 const guest_cr3, void* const gva, size_t* const offset_to_next_page) {
        auto const gpa = gva2gpa(guest_cr3, gva, offset_to_next_page);
        if (!gpa)
            return nullptr;
        return host_physical_memory_base + gpa;  //��gpaӳ�䵽hva
    }

    // translate a GVA to an HVA. offset_to_next_page is the number of bytes to
    // the next page (i.e. the number of bytes that can be safely accessed through
    // the HVA in order to modify the GVA.
    // �� GVA ����Ϊ HVA��offset_to_next_page ����һҳ���ֽ���������ͨ�� HVA ��ȫ�������޸� GVA ���ֽ�������
    void* gva2hva(void* const gva, size_t* const offset_to_next_page) {
        cr3 guest_cr3;
        guest_cr3.flags = vmread(GUEST_CR3);
        return gva2hva(guest_cr3, gva, offset_to_next_page);
    }

    //��GVAת��ΪGPA
    uint64_t get_physical_address(unsigned __int64 guest_cr3, _In_ PVOID BaseAddress)
    {
        if (!guest_cr3)
        {
            return NULL;
        }

        cr3 tmp_cr3;
        tmp_cr3.flags = guest_cr3;
        return gva2gpa(tmp_cr3, BaseAddress);
    }

    // attempt to read the memory at the specified guest virtual address from root-mode
    size_t read_guest_virtual_memory(cr3 const guest_cr3,
        void* const gva, void* const hva, size_t const size)
    {
        // the GVA that we're reading from
        auto const src = reinterpret_cast<uint8_t*>(gva);

        // the HVA that we're writing to
        // �����hva
        auto const dst = reinterpret_cast<uint8_t*>(hva);

        size_t bytes_read = 0;

        // translate and read 1 page at a time
        while (bytes_read < size) {
            size_t src_remaining = 0;

            // translate the guest virtual address to a host virtual address
            // ��guest�����ַӳ�䵽host�����ַ
            // �����ҳcurr_src����ָ����һ��ҳ
            auto const curr_src = gva2hva(guest_cr3, src + bytes_read, &src_remaining);

            // paged out
            if (!curr_src)
                return bytes_read;

            // the maximum allowed size that we can read at once with the translated HVA
            auto const curr_size = min(size - bytes_read, src_remaining);

            host_exception_info e = { 0 };
            memcpy_safe(e, dst + bytes_read, curr_src, curr_size);

            // this shouldn't ever happen...
            if (e.exception_occurred) {
                return bytes_read;
            }

            bytes_read += curr_size;
        }

        return bytes_read;
    }

    size_t write_guest_virtual_memory(cr3 const guest_cr3,
        void* const gva, void* const hva, size_t const size)
    {
        size_t bytes_read = 0;

        // �����gva
        auto const dst = reinterpret_cast<uint8_t*>(gva);

        // �����hva
        auto const src = reinterpret_cast<uint8_t*>(hva);

        while (bytes_read < size) {
            size_t dst_remaining = 0;

            // remaining����ҳ���ʣ���ֽ���
            // �����ҳcurr_dst����ָ����һ��ҳ
            auto const curr_dst = gva2hva(guest_cr3, dst + bytes_read, &dst_remaining);

            // this means that the target memory isn't paged in. there's nothing
            // we can do about that since we're not currently in that process's context.
            // ����ζ��Ŀ���ڴ�δ������ҳ�����ǶԴ�����Ϊ������Ϊ����Ŀǰ���ڸý��̵��������С�
            if (!curr_dst)
                return bytes_read;


            auto const curr_size = min(size - bytes_read, dst_remaining);

            host_exception_info e = { 0 };
            memcpy_safe(e, curr_dst, src + bytes_read, curr_size);

            if (e.exception_occurred) {
                // ����Ĳ�Ӧ�÷���������Զ����
                return bytes_read;
            }

            bytes_read += curr_size;
        }
        return bytes_read;
    }

    // attempt to read the memory at the specified guest virtual address from root-mode
    // ��ȡguest�е�ǰ���̵������ڴ�
    size_t read_guest_virtual_memory(void* const gva, void* const hva, size_t const size)
    {
        cr3 guest_cr3;
        guest_cr3.flags = vmread(GUEST_CR3);
        return read_guest_virtual_memory(guest_cr3, gva, hva, size);
    }

    // д��guest�е�ǰ���̵������ڴ�
    size_t write_guest_virtual_memory(void* const gva, void* const hva, size_t const size)
    {
        cr3 guest_cr3;
        guest_cr3.flags = vmread(GUEST_CR3);
        return write_guest_virtual_memory(guest_cr3, gva, hva, size);
    }

    // ��ȡ���������ַ��Ӧ�� EPT PTE
    //ept_pte* get_ept_pte(__ept_state& ept_state, uint64_t const physical_address, bool const force_split)
    //{
    //    pml4_virtual_address const addr = { reinterpret_cast<void*>(physical_address) };

    //    if (addr.pml4_idx != 0)
    //        return nullptr;

    //    if (addr.pdpt_idx >= EPT_PD_COUNT)
    //        return nullptr;

    //    auto& pde_2mb = ept_state.ept_page_table->pml2[addr.pdpt_idx][addr.pd_idx];

    //    if (pde_2mb.page_directory_entry.large_page) {
    //        if (!force_split)
    //            return nullptr;

    //        //�ָ�ept pdeҳ
    //        split_ept_pde(ept, &pde_2mb);

    //        // failed to split the PDE
    //        if (pde_2mb.large_page)
    //            return nullptr;
    //    }

    //    auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base
    //        + (ept.pds[addr.pdpt_idx][addr.pd_idx].page_frame_number << 12));

    //    return &pt[addr.pt_idx];
    //}


    // get the KPCR of the current guest (this pointer should stay constant per-vcpu)
    PKPCR current_guest_kpcr() {
        // GS base holds the KPCR when in ring-0
        if (current_guest_cpl() == 0)
            return reinterpret_cast<PKPCR>(vmread(GUEST_GS_BASE));

        // when in ring-3, the GS_SWAP contains the KPCR
        // �� ring-3 �У�GS_SWAP ���� �ں�KPCR
        return reinterpret_cast<PKPCR>(__readmsr(IA32_KERNEL_GS_BASE));
    }


    // get the ETHREAD of the current guest
    // ��ȡguest��ĵ�ǰ�̶߳���
    size_t current_guest_ethread()
    {
        // KPCR
        auto const kpcr = current_guest_kpcr();

        if (!kpcr)
            return NULL;

        // KPCR::Prcb
        auto const kprcb = reinterpret_cast<uint8_t*>(kpcr) + ghv.kpcr_pcrb_offset;

        // KPCRB::CurrentThread
        size_t current_thread = NULL;
        read_guest_virtual_memory(ghv.system_cr3,
            kprcb + ghv.kprcb_current_thread_offset,
            &current_thread,
            sizeof(current_thread));

        return current_thread;
    }


    //���ش����Ķϵ��guest������
    bool get_breakpoint_detected(__vcpu* vcpu, PBREAKPOINT_DETECTED vmcallinfo)
    {
        BREAKPOINT_DETECTED tmp_vmcallinfo = { 0 };

        if (sizeof(BREAKPOINT_DETECTED) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(BREAKPOINT_DETECTED)))
        {
            //��ȡ���ݿ��ܲ�����
            return false;
        }

        //�жϵ�ǰ�߼����������¼�Ĵ����ϵ��Ƿ��ǵ�������Ҫ��
        if (vcpu->Cid.UniqueThread == (HANDLE)tmp_vmcallinfo.Cid.UniqueThread)
        {
            tmp_vmcallinfo.breakpoint_detected = vcpu->breakpoint_detected;

            if (sizeof(BREAKPOINT_DETECTED) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(BREAKPOINT_DETECTED)))
            {
                //д�����ݿ��ܲ�����
                return false;
            }

            //��˵���öϵ��¼�������������������ʱ�����Ƴ���
            vcpu->breakpoint_detected = NULL;
            vcpu->Cid = { 0 };
            return true;
        }
        return false;
    }

    //��guestע��#DB�¼�
    void inject_single_step(__vcpu* vcpu)
    {
        //guest��ģʽ������ں˾Ͳ�ע��#DB
        int kernelmode = hv::get_guest_cpl() == 0;
        if (!kernelmode)
        {
            PCLIENT_ID Cid = GuestCurrentThreadCid();
            vcpu->Cid.UniqueThread = Cid->UniqueThread;  //��¼��ǰguest���߳�id
            hv::inject_interruption(EXCEPTION_VECTOR_SINGLE_STEP, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, false);
        }
    }


    //��ȡ���е�id
    int getIdleWatchID()
    {
        int i;
        for (i = 0; i < EPTWATCHLISTSIZE; i++)
        {
            if (eptWatchList[i].inuse == 0)  //����û�б�ʹ�õ�λ��
            {
                return i;  //�ҵ��󷵻�index
            }
        }
        return -1;
    }

    void InitGlobalVariables()
    {
        g_guest_cr3 = __readcr3();        
        __sgdt(&g_gdtr);                                 // ����ǰ�߼���������gdt�洢��ȫ�ֱ���g_gdtr��
        __sidt(&g_idtr);                                 // ����ǰ�߼���������idt�洢��ȫ�ֱ���g_idtr��
        g_guest_cr0 = __readcr0();
        g_guest_cr4 = __readcr4();
    }
}