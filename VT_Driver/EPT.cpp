#include "Driver.h"
#include "poolmanager.h"
#include "Globals.h"
#include "mtrr.h"
#include "EPT.h"
#include "msr.h"
#include "spinlock.h"
#include "AllocateMem.h"
#include "vmx.h"
#include "hypervisor_routines.h"
#include "vmcs.h"

EXTERN_C size_t __fastcall LDE(const void* lpData, unsigned int size);

namespace ept
{
	/// <summary>
	/// Build mtrr map to track physical memory type
	/// ����mtrrӳ���Ը��������ڴ�����(�ֳƻ�������)
	/// ���ȣ�����Ҫ�˽�MTRR��Memory Type Range Registers����ʲô��
	/// MTRR��һ��Ĵ��������ڶ��������ڴ��ַ��Χ�Ļ������ͣ������д����WB��ֱд����WT�ȣ���
	/// Ȼ������Ҫ��ȡϵͳ�е�MTRR������Ϣ������ͨ����ȡ�ͽ���ϵͳ��MTRR�Ĵ�������ȡ��Щ��Ϣ��
	/// ����ķ������������ϵͳ��Ӳ��ƽ̨���졣	
	/// ����MTRR������Ϣ������MTRRӳ�䡣�����Խ�MTRR������Ϣת��Ϊ�������ĸ�ʽ������ʹ�����ݽṹ����
	/// ����MTRR�����ã��������ڴ��ַ��Χӳ�䵽��Ӧ�Ļ������͡�		
	/// </summary>
	void build_mtrr_map()
	{
		__mtrr_cap_reg mtrr_cap = { 0 };
		__mtrr_physbase_reg current_phys_base = { 0 };
		__mtrr_physmask_reg current_phys_mask = { 0 };
		__mtrr_def_type mtrr_def_type = { 0 };
		__mtrr_range_descriptor* descriptor;

		//
		// �ڴ����ͷ�Χ�Ĵ��� (MTRR) �ṩ��һ�ֹ��������ڴ����͵Ļ���
		// ����ָ�������ڴ�Ļ������ͣ�����CPU���ܡ�

		mtrr_cap.all = __readmsr(IA32_MTRRCAP);

		//����û�б�MTRR�Ĵ������ǵ������ڴ�����ʹ��IA32_MTRR_DEF_TYPE�Ĵ�����ָ����Ĭ������
		mtrr_def_type.all = __readmsr(IA32_MTRR_DEF_TYPE);

		if (mtrr_def_type.mtrr_enabled == false)
		{
			// ���ɻ���
			// MTRRs����������ζ�����е������ڴ涼������ΪUC
			g_vmm_context.mtrr_info.default_memory_type = MEMORY_TYPE_UNCACHEABLE;
			return;
		}

		g_vmm_context.mtrr_info.default_memory_type = mtrr_def_type.memory_type;

		//�жϴ������Ƿ�֧��smrr
		if (mtrr_cap.smrr_support == true)
		{
			current_phys_base.all = __readmsr(IA32_SMRR_PHYSBASE);
			current_phys_mask.all = __readmsr(IA32_SMRR_PHYSMASK);

			if (current_phys_mask.valid && current_phys_base.type != mtrr_def_type.memory_type)
			{
				descriptor = &g_vmm_context.mtrr_info.memory_range[g_vmm_context.mtrr_info.enabled_memory_ranges++];
				descriptor->physcial_base_address = current_phys_base.physbase << PAGE_SHIFT;

				unsigned long bits_in_mask = 0;
				_BitScanForward64(&bits_in_mask, current_phys_mask.physmask << PAGE_SHIFT);

				descriptor->physcial_end_address = descriptor->physcial_base_address + ((1ULL << bits_in_mask) - 1ULL);
				descriptor->memory_type = (unsigned __int8)current_phys_base.type;
				descriptor->fixed_range = false;
			}
		}

		//�жϴ������Ƿ�֧�̶ֹ���ΧMTRR
		//MTRR ���������������ڴ��ж�������Χ����������һ��(MSR)�Ĵ���������ָ��ÿ����Χ�а������ڴ�����
		//�̶��ڴ淶Χӳ��Ϊ 11 ���̶���Χ�Ĵ�����ÿ���Ĵ��� 64 λ��ÿ���Ĵ�����Ϊ 8 ���ֶΣ�����ָ���Ĵ������Ƶ�ÿ���ӷ�Χ���ڴ����ͣ�
		if (mtrr_cap.fixed_range_support == true && mtrr_def_type.fixed_range_mtrr_enabled)
		{
			constexpr auto k64_base = 0x0;
			constexpr auto k64_size = 0x10000; //64KB
			constexpr auto k16_base = 0x80000;
			constexpr auto k16_size = 0x4000; //16KB
			constexpr auto k4_base = 0xC0000;
			constexpr auto k4_size = 0x1000; //4KB

			//�Ĵ��� IA32_MTRR_FIX64K_00000 �� ӳ�� 512 KB ��ַ��Χ���� 0H �� 7FFFFH���˷�Χ��Ϊ8�� 64 KB �ӷ�Χ��
			__mtrr_fixed_range_type k64_types = { __readmsr(IA32_MTRR_FIX64K_00000) };

			for (unsigned int i = 0; i < 8; i++)
			{
				descriptor = &g_vmm_context.mtrr_info.memory_range[g_vmm_context.mtrr_info.enabled_memory_ranges++];
				descriptor->memory_type = k64_types.types[i];
				descriptor->physcial_base_address = k64_base + (k64_size * i);
				descriptor->physcial_end_address = k64_base + (k64_size * i) + (k64_size - 1);
				descriptor->fixed_range = true;
			}

			//�Ĵ��� IA32_MTRR_FIX16K_80000 �� IA32_MTRR_FIX16K_A0000 �� ӳ������ 128 KB ��ַ��Χ���� 80000H �� BFFFFH��
			//ÿ���Ĵ��� 8 ����Χ��
			for (unsigned int i = 0; i < 2; i++)
			{
				__mtrr_fixed_range_type k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };

				for (unsigned int j = 0; j < 8; j++)
				{
					descriptor = &g_vmm_context.mtrr_info.memory_range[g_vmm_context.mtrr_info.enabled_memory_ranges++];
					descriptor->memory_type = k16_types.types[j];
					descriptor->physcial_base_address = (k16_base + (i * k16_size * 8)) + (k16_size * j);
					descriptor->physcial_end_address = (k16_base + (i * k16_size * 8)) + (k16_size * j) + (k16_size - 1);
					descriptor->fixed_range = true;
				}
			}

			//�Ĵ��� IA32_MTRR_FIX4K_C0000 �� IA32_MTRR_FIX4K_F8000 �� ӳ�� 8 �� 32 KB ��ַ��Χ��
			//�� C0000H �� FFFFFH���˷�Χ��Ϊ 64 �� 4 KB �ӷ�Χ��ÿ���Ĵ��� 8 ����Χ��
			for (unsigned int i = 0; i < 8; i++)
			{
				__mtrr_fixed_range_type k4_types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };

				for (unsigned int j = 0; j < 8; j++)
				{
					descriptor = &g_vmm_context.mtrr_info.memory_range[g_vmm_context.mtrr_info.enabled_memory_ranges++];
					descriptor->memory_type = k4_types.types[j];
					descriptor->physcial_base_address = (k4_base + (i * k4_size * 8)) + (k4_size * j);
					descriptor->physcial_end_address = (k4_base + (i * k4_size * 8)) + (k4_size * j) + (k4_size - 1);
					descriptor->fixed_range = true;
				}
			}
		}


		//Indicates the number of variable ranges
		//implemented on the processor.
		//�������пɱ�MTRRs�Ĵ�����������
		//Pentium 4��Intel Xeon �� P6 ϵ�д������������Ϊ m ���ɱ��С��ַ��Χָ���ڴ����ͣ�ÿ����Χʹ��һ�� MTRR��
		//֧�ֵķ�Χ�� m �� IA32_MTRRCAP MSR ��λ 7:0 �и���
		for (int i = 0; i < mtrr_cap.range_register_number; i++)
		{
			// ÿ���еĵ�һ����Ŀ��IA32_MTRR_PHYSBASEn�����巶Χ�Ļ���ַ���ڴ����ͣ�
			//
			current_phys_base.all = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
			current_phys_mask.all = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

			//
			// If range is enabled
			// ������÷�Χ
			if (current_phys_mask.valid && current_phys_base.type != mtrr_def_type.memory_type)
			{
				descriptor = &g_vmm_context.mtrr_info.memory_range[g_vmm_context.mtrr_info.enabled_memory_ranges++];

				//
				// Calculate base address, physbase is truncated by 12 bits so we have to left shift it by 12
				// �����ַ��physbase ���ض��� 12 λ��������Ǳ��뽫������ 12
				//
				descriptor->physcial_base_address = current_phys_base.physbase << PAGE_SHIFT;

				//
				// Index of first bit set to one determines how much do we have to bit shift to get size of range
				// physmask is truncated by 12 bits so we have to left shift it by 12
				// ��һ������Ϊ 1 ��λ������������������Ҫ��λ����λ���ܵõ���Χ physmask �Ĵ�С��
				// �����ض��� 12 λ���������Ǳ��뽫������ 12 λ
				//
				unsigned long bits_in_mask = 0;
				_BitScanForward64(&bits_in_mask, current_phys_mask.physmask << PAGE_SHIFT);

				//
				// Calculate the end of range specified by mtrr
				// ���� mtrr ָ���ķ�Χ�Ľ���λ��
				//
				descriptor->physcial_end_address = descriptor->physcial_base_address + ((1ULL << bits_in_mask) - 1ULL);

				//
				// Get memory type of range
				// ��ȡ��Χ���ڴ�����
				//
				descriptor->memory_type = (unsigned __int8)current_phys_base.type;
				descriptor->fixed_range = false;
			}
		}
	}

	/// <summary>
	/// Get page cache memory type
	/// ��ȡҳ�����ڴ�����
	/// </summary>
	/// <param name="pfn"></param>
	/// <param name="is_large_page"></param>  �Ǵ�ҳ��
	/// <returns></returns>
	unsigned __int8 get_memory_type(unsigned __int64 pfn, bool is_large_page)
	{
		unsigned __int64 page_start_address = is_large_page == true ? pfn * LARGE_PAGE_SIZE : pfn * PAGE_SIZE;
		unsigned __int64 page_end_address = is_large_page == true ? (pfn * LARGE_PAGE_SIZE) + (LARGE_PAGE_SIZE - 1) : (pfn * PAGE_SIZE) + (PAGE_SIZE - 1);

		//δ�� MTRR ӳ��ĵ�ַ��ΧӦ����ΪĬ������
		unsigned __int8 memory_type = g_vmm_context.mtrr_info.default_memory_type;

		//��MTRR��Ѱ�Ҹ�����ַ���ڴ�����
		for (unsigned int i = 0; i < g_vmm_context.mtrr_info.enabled_memory_ranges; i++)
		{
			if (page_start_address >= g_vmm_context.mtrr_info.memory_range[i].physcial_base_address &&
				page_end_address <= g_vmm_context.mtrr_info.memory_range[i].physcial_end_address)
			{
				memory_type = g_vmm_context.mtrr_info.memory_range[i].memory_type;

				//�̶���Χ
				if (g_vmm_context.mtrr_info.memory_range[i].fixed_range == true)
					break;

				if (memory_type == MEMORY_TYPE_UNCACHEABLE)  //���ɻ���
					break;
			}
		}

		return memory_type;
	}

	/// <summary>
	/// Check if potential large page doesn't land on two or more different cache memory types
	/// </summary>
	/// <param name="pfn"></param>
	/// <returns></returns>
	bool is_valid_for_large_page(unsigned __int64 pfn)
	{
		unsigned __int64 page_start_address = pfn * LARGE_PAGE_SIZE;
		unsigned __int64 page_end_address = (pfn * LARGE_PAGE_SIZE) + (LARGE_PAGE_SIZE - 1);

		for (unsigned int i = 0; i < g_vmm_context.mtrr_info.enabled_memory_ranges; i++)
		{
			if (page_start_address <= g_vmm_context.mtrr_info.memory_range[i].physcial_end_address &&
				page_end_address > g_vmm_context.mtrr_info.memory_range[i].physcial_end_address)
				return false;

			else if (page_start_address < g_vmm_context.mtrr_info.memory_range[i].physcial_base_address &&
				page_end_address >= g_vmm_context.mtrr_info.memory_range[i].physcial_base_address)
				return false;
		}

		return true;
	}

	/// <summary> 
	/// Setup page memory type
	/// ����ҳ�ڴ�����
	/// </summary>
	/// <param name="entry"> Pointer to pml2 entry </param>
	/// <param name="pfn"> Page frame number </param>
	bool setup_pml2_entry(mtrr_data const& mtrrs, __ept_state& ept_state, __ept_pde& entry, unsigned __int64 pfn)
	{
		entry.page_directory_entry.page_frame_number = pfn;

		//�ж��Ƿ��Ǵ�ҳ��
		if (is_valid_for_large_page(pfn) == true)
		{
			entry.page_directory_entry.memory_type = get_memory_type(pfn, true);
			//entry.page_directory_entry.memory_type = hv::calc_mtrr_mem_type(mtrrs, pfn << 21, 0x1000 << 9);
			return true;
		}
		else
		{
			//���Ǵ�ҳ���� ˵����PTҳ�� 
			//����PTҳ��
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("Failed to allocate split buffer");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			return split_pml2(mtrrs, ept_state, split_buffer, pfn * LARGE_PAGE_SIZE);
		}
	}

	/// <summary>
	/// Create ept page table
	/// ����eptҳ��
	/// </summary>
	/// <returns> status </returns>
	bool create_ept_page_table(__ept_state& ept_state)
	{
		PHYSICAL_ADDRESS max_size;
		max_size.QuadPart = MAXULONG64;

		ept_state.ept_page_table = allocate_pool<__vmm_ept_page_table>();
		if (ept_state.ept_page_table == NULL)
		{
			outDebug("Failed to allocate memory for PageTable.\n");
			return false;
		}

		__vmm_ept_page_table* page_table = ept_state.ept_page_table;
		RtlSecureZeroMemory(page_table, sizeof(__vmm_ept_page_table));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		// ������ҳ������Ϊ rwx���Է�ֹ����Ҫ�� ept Υ��
		// ���õ�һ�� PML4E��ʹ��ָ�����ǵ� PDPT
		//
		page_table->pml4[0].page_frame_number = GET_PFN(MmGetPhysicalAddress(&page_table->pml3[0]).QuadPart);
		page_table->pml4[0].read = 1;
		page_table->pml4[0].write = 1;
		page_table->pml4[0].execute = 1;
		page_table->pml4[0].execute_for_usermode = 0;

		__ept_pdpte pdpte_template = { 0 };

		pdpte_template.read = 1;
		pdpte_template.write = 1;
		pdpte_template.execute = 1;
		pdpte_template.execute_for_usermode = 0;

		__stosq((unsigned __int64*)&page_table->pml3[0], pdpte_template.all, 512);

		for (int i = 0; i < 512; i++)
			page_table->pml3[i].page_frame_number = GET_PFN(MmGetPhysicalAddress(&page_table->pml2[i][0]).QuadPart);

		__ept_pde pde_template = { 0 };

		pde_template.page_directory_entry.read = 1;
		pde_template.page_directory_entry.write = 1;
		pde_template.page_directory_entry.execute = 1;

		pde_template.page_directory_entry.large_page = 1;  //ʹ�ô�ҳ�� 2mb
		pde_template.page_directory_entry.execute_for_usermode = 0;

		__stosq((unsigned __int64*)&page_table->pml2[0], pde_template.all, 512 * 512);

		// MTRR data for setting memory types
		// ���������ڴ����͵� MTRR ����
		auto const mtrrs = hv::read_mtrr_data();
		g_vmm_context.mtrr_info.mtrrs = mtrrs;
		for (int i = 0; i < 512; i++)
		{
			for (int j = 0; j < 512; j++)
			{
				if (setup_pml2_entry(mtrrs, ept_state, page_table->pml2[i][j], (i * 512) + j) == false)
				{
					outDebug("setup_pml2_entryʧ��\n");
					return false;
				}					
			}
		}

		return true;
	}

	bool create_ept_page_table2(__ept_state& ept_state)
	{
		PHYSICAL_ADDRESS max_size;
		max_size.QuadPart = MAXULONG64;

		ept_state.ept_page_table = allocate_pool<__vmm_ept_page_table>();
		if (ept_state.ept_page_table == NULL)
		{
			LogError("Failed to allocate memory for PageTable");
			return false;
		}

		__vmm_ept_page_table* page_table = ept_state.ept_page_table;
		RtlSecureZeroMemory(page_table, sizeof(__vmm_ept_page_table));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		// ������ҳ������Ϊ rwx���Է�ֹ����Ҫ�� ept Υ��
		// ���õ�һ�� PML4E��ʹ��ָ�����ǵ� PDPT
		//
		page_table->pml4[0].page_frame_number = GET_PFN(MmGetPhysicalAddress(&page_table->pml3[0]).QuadPart);
		page_table->pml4[0].read = 1;
		page_table->pml4[0].write = 1;
		page_table->pml4[0].execute = 1;
		page_table->pml4[0].execute_for_usermode = 1;

		auto const mtrrs = hv::read_mtrr_data();

		// TODO: allocate a PT for the fixed MTRRs region so that we can get
		// more accurate memory typing in that area (as opposed to just
		// mapping the whole PDE as UC).
		// Ϊ�̶� MTRR �������һ�� PTҳ���Ա����ǿ����ڸ������ø�׼ȷ���ڴ����ͣ������ǽ������� PDE ӳ��Ϊ UC����

		for (size_t i = 0; i < EPT_PD_COUNT; ++i) {
			// point each PDPTE to the corresponding PD
			// ��ÿ�� PDPTE ָ����Ӧ�� PD
			auto& pdpte = page_table->pml3[i];
			pdpte.read = 1;
			pdpte.write = 1;
			pdpte.execute = 1;
			pdpte.accessed = 0;
			pdpte.execute_for_usermode = 1;
			pdpte.page_frame_number = GET_PFN(MmGetPhysicalAddress(&page_table->pml2[i][0]).QuadPart);

			for (size_t j = 0; j < 512; ++j) {
				// identity-map every GPA to the corresponding HPA
				auto& pde = page_table->pml2[i][j];
				pde.page_directory_entry.read = 1;
				pde.page_directory_entry.write = 1;
				pde.page_directory_entry.execute = 1;
				pde.page_directory_entry.ignore_pat = 0;
				pde.page_directory_entry.large_page = 1;  //��ʾpdeδ�ָ�
				pde.page_directory_entry.accessed = 0;
				pde.page_directory_entry.dirty = 0;
				pde.page_directory_entry.execute_for_usermode = 1;
				pde.page_directory_entry.page_frame_number = (i << 9) + j;
				pde.page_directory_entry.memory_type = hv::calc_mtrr_mem_type(mtrrs, pde.page_directory_entry.page_frame_number << 21/*2mb����*/, 0x1000 << 9/*2mb��С*/);
			}
		}

		return true;
	}

	/// <summary>
	/// Initialize ept structure
	/// </summary>
	/// <returns></returns>
	bool initialize(__ept_state& ept_state)
	{
		__eptp* ept_pointer = allocate_pool<__eptp*>(PAGE_SIZE);
		if (ept_pointer == NULL)
		{
			outDebug("ept_pointer ��ָ��\n");
			return false;
		}			

		RtlSecureZeroMemory(ept_pointer, PAGE_SIZE);

		if (create_ept_page_table(ept_state) == false)
		{
			outDebug("create_ept_page_tableʧ��\n");
			return false;
		}			

		//ept_pointer->memory_type = g_vmm_context.mtrr_info.default_memory_type;
		//��ǰ VMX �ܹ�ֻ֧�� UC��WB
		ept_pointer->memory_type = MEMORY_TYPE_WRITE_BACK;

		// Indicates 4 level paging
		// ʹ��4����ҳ
		ept_pointer->page_walk_length = 3;

		//ע����Ϊ������ӳ���pml4[0]
		//��������&ept_state.ept_page_table->pml4������ȡ��pml4[0]�ĵ�ַ
		ept_pointer->pml4_address = GET_PFN(MmGetPhysicalAddress(&ept_state.ept_page_table->pml4).QuadPart);

		ept_state.ept_pointer = ept_pointer;

		return true;
	}

	/// <summary>
	/// Get pml2 entry
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns> pointer to pml2 </returns>
	__ept_pde* get_pml2_entry(__ept_state& ept_state, unsigned __int64 physical_address)
	{
		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		//pml4_index����Ϊ0����Ϊ����ӳ�����ept pml4[0],����pml4_index����0����Ŀ������Ч��Ŀ
		//��ΪeptĿǰֻ֧��ӳ��һ��pml4e��һ��pml4e��Ŀ512GB��С
		if (pml4_index > 0)
		{
			LogError("512GB ���ϵĵ�ַ��Ч");
			return nullptr;
		}

		//��eptҳ����ȡpde
		return &ept_state.ept_page_table->pml2[pml3_index][pml2_index];
	}

	/// <summary>
	/// ����GPAȡ��ept��pte
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns></returns>
	__ept_pte* get_pml1_entry(__ept_state& ept_state, unsigned __int64 physical_address)
	{
		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		if (pml4_index > 0)
		{
			LogError("Address above 512GB is invalid");
			return nullptr;
		}

		__ept_pde* pml2 = &ept_state.ept_page_table->pml2[pml3_index][pml2_index];
		if (pml2->page_directory_entry.large_page == 1)
		{
			return nullptr;
		}

		PHYSICAL_ADDRESS pfn;
		pfn.QuadPart = pml2->large_page.page_frame_number << PAGE_SHIFT;
		__ept_pte* pml1 = (__ept_pte*)MmGetVirtualForPhysical(pfn);

		if (pml1 == nullptr)
		{
			return nullptr;
		}

		pml1 = &pml1[MASK_EPT_PML1_INDEX(physical_address)];
		return pml1;
	}

	/// <summary>
	/// Split pml2 into 512 pml1 entries (From one 2MB page to 512 4KB pages)
	/// ��pml2���Ϊ512��pml1�� (��һ��2MBҳ�浽512��4KBҳ��)
	/// </summary>
	/// <param name="pre_allocated_buffer"> Pre allocated buffer for split </param>
	/// <param name="physical_address"></param>
	/// <returns> status </returns>
	bool split_pml2(mtrr_data const& mtrrs, __ept_state& ept_state, void* pre_allocated_buffer, unsigned __int64 physical_address)
	{
		__ept_pde* pde = get_pml2_entry(ept_state, physical_address);
		if (pde == NULL)
		{
			LogError("Invalid address passed");
			return false;
		}

		//��ʼ��ptҳ��
		__ept_dynamic_split* new_split = (__ept_dynamic_split*)pre_allocated_buffer;
		RtlSecureZeroMemory(new_split, sizeof(__ept_dynamic_split));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		// ������ҳ������Ϊ rwx���Է�ֹ����Ҫ�� ept Υ��
		//
		new_split->entry = pde;

		__ept_pte entry_template = { 0 };
		entry_template.read = 1;
		entry_template.write = 1;
		entry_template.execute = 1;
		entry_template.ept_memory_type = pde->page_directory_entry.memory_type;
		entry_template.ignore_pat = pde->page_directory_entry.ignore_pat;
		entry_template.suppress_ve = pde->page_directory_entry.suppressve;

		__stosq((unsigned __int64*)&new_split->pml1[0], entry_template.all, 512);
		for (int i = 0; i < 512; i++)
		{
			//�ȼ�pte.page_frame_number = (pde_2mb->page_frame_number << 9) + i;
			unsigned __int64 pfn = ((pde->page_directory_entry.page_frame_number * LARGE_PAGE_SIZE) >> PAGE_SHIFT) + i;
			new_split->pml1[i].page_frame_number = pfn;
			new_split->pml1[i].ept_memory_type = get_memory_type(pfn, false);
			//new_split->pml1[i].ept_memory_type = hv::calc_mtrr_mem_type(mtrrs, pfn << 21, 0x1000 << 9);
		}

		__ept_pde new_entry = { 0 };
		new_entry.large_page.read = 1;
		new_entry.large_page.write = 1;
		new_entry.large_page.execute = 1;

		new_entry.large_page.page_frame_number = MmGetPhysicalAddress(&new_split->pml1[0]).QuadPart >> PAGE_SHIFT;

		RtlCopyMemory(pde, &new_entry, sizeof(new_entry));

		return true;
	}

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// ��������ҳ�沢ˢ��tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	/// <param name="invalidation_type"> Specifiy if we want to invalidate single context or all contexts  </param>
	void swap_pml1_and_invalidate_tlb(__ept_state& ept_state, __ept_pte* entry_address, __ept_pte entry_value, invept_type invalidation_type)
	{
		// �������ģʽ������cpu�˹���һ��ept���ʶ�Ҫ����
		// Ŀǰ�������ÿ��cpu����һ��eptҳ������������
		// Acquire the lock
		//spinlock::lock(&g_vmm_context.pml_lock);

		// Set the value
		entry_address->all = entry_value.all;

		// Invalidate the cache
		if (invalidation_type == invept_single_context)
		{
			invept_single_context_func(ept_state.ept_pointer->all);
		}
		else
		{
			invept_all_contexts_func();
		}

		// Release the lock
		//spinlock::unlock(&g_vmm_context.pml_lock);
	}

	/// <summary>
	/// Write an absolute jump, We aren't touching any register except stack so it's the most safest trampoline
	/// Size: 14 bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="destination_address"> Address of place where we want to jump </param>
	void hook_write_absolute_jump(unsigned __int8* target_buffer, unsigned __int64 destination_address)
	{
		// push lower 32 bits of destination address	
		target_buffer[0] = 0x68;
		*((unsigned __int32*)&target_buffer[1]) = (unsigned __int32)destination_address;

		// mov dword ptr [rsp + 4]
		target_buffer[5] = 0xc7;
		target_buffer[6] = 0x44;
		target_buffer[7] = 0x24;
		target_buffer[8] = 0x04;

		// higher 32 bits of destination address	
		*((unsigned __int32*)&target_buffer[9]) = (unsigned __int32)(destination_address >> 32);

		// ret
		target_buffer[13] = 0xc3;
	}

	/// <summary>
	/// Write relative jump,
	/// Size: 5 Bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="destination_address"> Address where we want to jump </param>
	/// <param name="source_address"> Address from which we want to jump </param>
	void hook_write_relative_jump(unsigned __int8* target_buffer, unsigned __int64 destination_address, unsigned __int64 source_address)
	{
		// destination - (source + sizeof instruction)
		__int32 jmp_value = destination_address - (source_address + 0x5);

		// relative jmp opcode
		target_buffer[0] = 0xe9;

		// set jmp offset
		*((__int32*)&target_buffer[1]) = jmp_value;
	}

	//��vmcallָ��д��α��ҳ  ͨ������vmcall��ʵ��hook
	bool write_vmcall_instruction_to_memory(__ept_hooked_function_info* hooked_function_info, void* target_function, void* proxy_function, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 0;

		// Get offset of hooked function within page
		// ������Ե�ַ�ĵ�12λ ҳƫ��
		unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);
		unsigned __int8* target_buffer = &hooked_function_info->fake_page_contents[page_offset];
		target_buffer[0] = 0x0f;
		target_buffer[1] = 0x01;
		target_buffer[2] = 0xC1;  //0F 01 C1 vmcall
		hooked_function_info->handler_function = proxy_function;

		//DbgBreakPoint();
		if (origin_function)
		{
			//���㱻�޸ĵ�ָ��ռ�ö����ֽ�
			while (hooked_instructions_size < 3)
				hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);

			hooked_function_info->hook_size = hooked_instructions_size;

			// Copy overwritten instructions to trampoline buffer
			// �����ǵ�ָ��ݵ����建����
			RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

			// Add the absolute jump back to the original function.
			// ��Ӿ�����ת�ص�ԭ���ĺ���
			hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

			// Return to user address of trampoline to call original function
			*origin_function = hooked_function_info->first_trampoline_address;
		}

		return true;
	}

	//��int3ָ��д��α��ҳ  ͨ������int3�ж���ʵ��hook
	bool write_cc_instruction_to_memory(__ept_hooked_function_info* hooked_function_info, void* target_function, void* proxy_function, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 1;

		// Get offset of hooked function within page
		// ������Ե�ַ�ĵ�12λ ҳƫ��
		unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);
		hooked_function_info->hook_size = hooked_instructions_size;
		unsigned __int8* target_buffer = &hooked_function_info->fake_page_contents[page_offset];
		target_buffer[0] = 0xCC;
		hooked_function_info->handler_function = proxy_function;  //int3�Ĵ�����

		if (origin_function)
		{
			//���㱻�޸ĵ�ָ��ռ�ö����ֽ�
			hooked_instructions_size = LDE((unsigned __int8*)target_function, 64);

			// Copy overwritten instructions to trampoline buffer
			// �����ǵ�ָ��Ƶ����建����
			RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

			// Add the absolute jump back to the original function.
			// ��Ӿ�����ת�ص�ԭ���ĺ���
			hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

			// Return to user address of trampoline to call original function
			*origin_function = hooked_function_info->first_trampoline_address;
		}

		return true;
	}

	//��int1д��αҳ  ����hook
	bool write_int1_instruction_to_memory(__ept_hooked_function_info* hooked_function_info, void* target_function, void* proxy_function, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 1;

		// Get offset of hooked function within page
		// ������Ե�ַ�ĵ�12λ ҳƫ��
		unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);
		hooked_function_info->hook_size = hooked_instructions_size;
		unsigned __int8* target_buffer = &hooked_function_info->fake_page_contents[page_offset];
		target_buffer[0] = 0xf1;  //int1
		hooked_function_info->handler_function = proxy_function;  //int1�Ĵ�����

		if (origin_function)
		{
			//���㱻�޸ĵ�ָ��ռ�ö����ֽ�
			hooked_instructions_size = LDE((unsigned __int8*)target_function, 64);

			// Copy overwritten instructions to trampoline buffer
			// �����ǵ�ָ��Ƶ����建����
			RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

			// Add the absolute jump back to the original function.
			// ��Ӿ�����ת�ص�ԭ���ĺ���
			hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

			// Return to user address of trampoline to call original function
			*origin_function = hooked_function_info->first_trampoline_address;
		}

		return true;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="hooked_page"> Pointer to __ept_hooked_page_info structure which holds info about hooked page </param>
	/// <param name="target_function"> Address of function which we want to hook </param>
	/// <param name="proxy_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_instruction_memory(__ept_state& ept_state, __ept_hooked_function_info* hooked_function_info, void* target_function, void* proxy_function, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 0;

		// Get offset of hooked function within page
		// ������Ե�ַ�ĵ�12λ ҳƫ��
		unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);

		//if (trampoline != 0)
		//{
		//	hooked_instructions_size = 0;

		//	// If first 5 bytes of function are on 2 separate pages then return (Hypervisor doesn't support function hooking at page boundaries)
		//	if ((page_offset + 5) > PAGE_SIZE - 1)
		//	{
		//		LogError("Function at page boundary");
		//		return false;
		//	}

		//	while (hooked_instructions_size < 5)
		//	{
		//		hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);
		//	}

		//	// If instructions to hook are on two seperate pages then stop hooking (Hypervisor doesn't support function hooking at page boundaries)
		//	if ((hooked_instructions_size + 5) > PAGE_SIZE - 1)
		//	{
		//		LogError("ҳ��߽紦�ĺ���");
		//		return false;
		//	}

		//	hooked_function_info->hook_size = hooked_instructions_size;

		//	//��α��ҳ�ﹹ�������ת
		//	hook_write_relative_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)trampoline, (unsigned __int64)target_function);

		//	//����ԭʼ����
		//	//����Դ�����ֽ�
		//	RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);
		//	//��������
		//	hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

		//	//Դ����
		//	*origin_function = hooked_function_info->first_trampoline_address;

		//	return hook_function(ept_state, trampoline, proxy_function, nullptr);
		//}

		// If first 14 bytes of function are on 2 separate pages then return (Hypervisor doesn't support function hooking at page boundaries)
		// �ж�ҳƫ�� >4095  ���ж��Ƿ���뵽��һ��4Kҳ��
		if ((page_offset + 14) > PAGE_SIZE - 1)
		{
			LogError("Function at page boundary");
			return false;
		}

		// Get the full size of instructions necessary to copy
		while (hooked_instructions_size < 14)
			hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);


		// If instructions to hook are on two seperate pages then return (Hypervisor doesn't support function hooking at page boundaries)
		if ((hooked_instructions_size + 14) > PAGE_SIZE - 1)
		{
			LogError("Function at page boundary");
			return false;
		}

		hooked_function_info->hook_size = hooked_instructions_size;

		//
		// Now it's trampoline so we don't have to store origin function
		if (origin_function == nullptr)
		{
			hook_write_absolute_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)proxy_function);

			return true;
		}

		// Copy overwritten instructions to trampoline buffer
		RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

		// Add the absolute jump back to the original function.
		hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

		// Return to user address of trampoline to call original function
		*origin_function = hooked_function_info->first_trampoline_address;

		// Write the absolute jump to our shadow page memory to jump to our hooked_page.
		hook_write_absolute_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)proxy_function);

		return true;
	}

	bool is_page_splitted(__ept_state& ept_state, unsigned __int64 physical_address)
	{
		__ept_pde* entry = get_pml2_entry(ept_state, physical_address);
		return !entry->page_directory_entry.large_page;
	}

	//���������vmcall hook�ĵ�ַ��ת��������
	bool handler_vmcall_rip(__ept_state& ept_state)
	{
		unsigned __int64 guest_rip = hv::vmread(GUEST_RIP);
		unsigned __int64 physical_address = hv::get_physical_address(hv::ghv.system_cr3.flags, (PVOID)guest_rip);

		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				//LogInfo("ҳ���ѹҹ�");

				//��������ַ�Ƿ��Ѿ��ҹ�
				PLIST_ENTRY current_hooked_function = &hooked_page_info->hooked_functions_list;
				while (&hooked_page_info->hooked_functions_list != current_hooked_function->Flink)
				{
					current_hooked_function = current_hooked_function->Flink;
					__ept_hooked_function_info* hooked_function_info = CONTAINING_RECORD(current_hooked_function, __ept_hooked_function_info, hooked_function_list);

					if (hooked_function_info->virtual_address == (PVOID)guest_rip)
					{
						hv::vmwrite(GUEST_RIP, hooked_function_info->handler_function);
						return true;
					}
				}
			}
		}
		return false;
	}

	//ͨ��vmcall����hook ��vmcallָ����뵽Ŀ�����
	bool vmcall_hook_function(__ept_state& ept_state, 
		void* target_function/*���ҹ��ĺ�����ַ*/, 
		void* proxy_function/*�º�����ַ*/, 
		void** origin_function,
		unsigned __int64 target_cr3)
	{
		//unsigned __int64 physical_address = hv::get_physical_address(target_cr3, (PVOID)target_function);
		unsigned __int64 physical_address = MmGetPhysicalAddress(target_function).QuadPart;

		//
		// ���ú����Ƿ�����������ڴ���
		// ����ú����������ַΪ��
		// ˵���ú����������������ڴ���
		//
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				if (hooked_page_info->Options == EPTO_HOOK_FUNCTION)
				{
					LogInfo("ҳ���ѹҹ�");

					__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, TRUE, sizeof(__ept_hooked_function_info));
					if (hooked_function_info == nullptr)
					{
						LogError("�ҹ������ṹû��Ԥ�ȷ�����ڴ�");
						return false;
					}

					//
					// If we are hooking code cave for second trampoline 
					// then origin function in null and we don't have to get pool for trampoline
					//
					if (origin_function != nullptr)
					{
						hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
						if (hooked_function_info->first_trampoline_address == nullptr)
						{
							pool_manager::release_pool(hooked_function_info);
							LogError("There is no pre-allocated pool for trampoline");
							return false;
						}
					}

					hooked_function_info->virtual_address = target_function;
					hooked_function_info->breakpoint_address = NULL;

					hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

					if (write_vmcall_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
					{
						if (hooked_function_info->first_trampoline_address != nullptr)
							pool_manager::release_pool(hooked_function_info->first_trampoline_address);
						pool_manager::release_pool(hooked_function_info);
						LogError("Hook failed");
						return false;
					}

					// Track all hooked functions within page
					InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

					return true;
				}
			}
		}

		//�ж�2mb pde�Ƿ��Ѿ����зָ�
		if (is_page_splitted(ept_state, physical_address) == false)
		{
			//����ptҳ��
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		//�õ�Ŀ��ҳ
		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, true, sizeof(__ept_hooked_function_info));
		if (hooked_function_info == nullptr)
		{
			pool_manager::release_pool(hooked_page_info);
			LogError("hook����ʱԤ����Ļ����Ѻľ�");
			return false;
		}

		//
		// If we are hooking code cave for second trampoline 
		// then origin function in null and we don't have to get pool for trampoline
		//
		if (origin_function != nullptr)
		{
			hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
			if (hooked_function_info->first_trampoline_address == nullptr)
			{
				pool_manager::release_pool(hooked_page_info);
				pool_manager::release_pool(hooked_function_info);
				LogError("There is no pre-allocated pool for trampoline");
				return false;
			}
		}

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		//�ȸ�ԭҳΪ����ִ�� �ص�guest��ִ�оʹ���vmexit
		//����vmm�󽻻�α��ҳ
		hooked_page_info->entry_address->execute = 0;
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;

		hooked_page_info->original_entry = *target_page;
		hooked_page_info->changed_entry = *target_page;

		//α��ҳ���ö�д		
		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		//��α��ҳ����ȥ
		hooked_page_info->changed_entry.page_frame_number = hooked_page_info->pfn_of_fake_page_contents;

		RtlCopyMemory(&hooked_page_info->fake_page_contents, PAGE_ALIGN(target_function), PAGE_SIZE);

		hooked_function_info->virtual_address = target_function;
		hooked_function_info->breakpoint_address = NULL;

		hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

		//��ʼhook
		if (write_vmcall_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
		{
			if (hooked_function_info->first_trampoline_address != nullptr)
				pool_manager::release_pool(hooked_function_info->first_trampoline_address);
			pool_manager::release_pool(hooked_function_info);
			pool_manager::release_pool(hooked_page_info);
			LogError("Hook failed");
			return false;
		}

		hooked_page_info->Options = EPTO_HOOK_FUNCTION;

		//��¼hook�ĺ�����ҳ �Ա��պ��ͷ�
		// Track all hooked functions
		InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		invept_single_context_func(ept_state.ept_pointer->all);

		return true;
	}

	//дα��ҳ�ڴ�
	bool write_fake_page_memory(__ept_hooked_function_info* hooked_function_info, void* target_address, void* buffer, unsigned __int64 buffer_size)
	{
		if ((hooked_function_info != NULL) && (target_address != NULL) && (buffer != NULL))
		{
			// Get offset of hooked function within page
			// ������Ե�ַ�ĵ�12λ ҳƫ��
			// �õ����޸ĵ�ָ����ҳ�ڵ�ƫ��
			unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_address);
			RtlCopyMemory(&hooked_function_info->fake_page_contents[page_offset], buffer, buffer_size);
		}
		return true;
	}

	//��α��ҳ�ڴ�
	bool read_fake_page_memory(__ept_hooked_function_info* hooked_function_info, void* target_address, void* buffer, unsigned __int64 buffer_size)
	{
		if ((hooked_function_info != NULL) && (target_address != NULL) && (buffer != NULL))
		{
			// Get offset of hooked function within page
			// ������Ե�ַ�ĵ�12λ ҳƫ��
			// �õ�����ȡ��ָ����ҳ�ڵ�ƫ��
			unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_address);
			RtlCopyMemory(buffer, &hooked_function_info->fake_page_contents[page_offset], buffer_size);
		}
		return true;
	}

	//��ȡ��������ϵ�
	bool get_hide_software_breakpoint(__ept_state& ept_state, PVT_BREAK_POINT vmcallinfo)
	{
		VT_BREAK_POINT tmp_vmcallinfo = { 0 };

		if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
		{
			//��ȡ���ݿ��ܲ�����
			return false;
		}

		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(tmp_vmcallinfo.PhysicalAddress))
			{
				if (hooked_page_info->Options == EPTO_VIRTUAL_BREAKPOINT)
				{
					LogInfo("ҳ���ѹҹ�");

					int offset = tmp_vmcallinfo.VirtualAddress & 0xFFF;
					memcpy(&tmp_vmcallinfo.buffer[0], &hooked_page_info->fake_page_contents[offset], tmp_vmcallinfo.Size);

					//���ظ�������
					if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
					{
						//д�����ݿ��ܲ�����
						return false;
					}

					return true;
				}
			}
		}

		//cr3 guest_cr3;
		//guest_cr3.flags = tmp_vmcallinfo.cr3;

		////��Ŀ����̵��ڴ�
		//if (tmp_vmcallinfo.Size != hv::read_guest_virtual_memory(guest_cr3, 
		//	(PVOID)tmp_vmcallinfo.VirtualAddress, 
		//	&tmp_vmcallinfo.buffer[0], 
		//	tmp_vmcallinfo.Size))
		//{
		//	//��ȡ���ݿ��ܲ�����
		//	return false;
		//}

		return false;
	}

	//����cc�ϵ�
	bool hide_cc_breakpoint(__ept_state& ept_state,
		VT_BREAK_POINT vmcallinfo,
		unsigned __int64 physical_address,
		unsigned __int64 Type)
	{
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				if (hooked_page_info->Options == EPTO_VIRTUAL_BREAKPOINT)
				{
					LogInfo("ҳ���ѹҹ�");

					//д��cc�ϵ�
					int offset = vmcallinfo.VirtualAddress & 0xFFF;
					hooked_page_info->fake_page_contents[offset] = 0xCC;

					return true;
				}
			}
		}

		//�ж�2mb pde�Ƿ��Ѿ����зָ�
		if (is_page_splitted(ept_state, physical_address) == false)
		{
			//����ptҳ��
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		//�õ�Ŀ��ҳ
		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		//��ԭҳ�޸�Ϊ����ִ��
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;
		hooked_page_info->entry_address->execute = 0;

		hooked_page_info->original_entry = *target_page;  //ָ��ԭ
		hooked_page_info->changed_entry = *target_page;

		//αҳ���ɶ�д
		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		//ָ��αҳpfn
		hooked_page_info->changed_entry.page_frame_number = hooked_page_info->pfn_of_fake_page_contents;

		hooked_page_info->Options = EPTO_VIRTUAL_BREAKPOINT;

		cr3 guest_cr3;
		guest_cr3.flags = vmcallinfo.cr3;

		//����Ŀ�����ԭҳ����
		if (PAGE_SIZE != hv::read_guest_virtual_memory(guest_cr3, PAGE_ALIGN(vmcallinfo.VirtualAddress), &hooked_page_info->fake_page_contents, PAGE_SIZE))
		{
			//��ȡ���ݿ��ܲ�����
			return false;
		}

		//д��cc�ϵ�
		int offset = vmcallinfo.VirtualAddress & 0xFFF;
		hooked_page_info->fake_page_contents[offset] = 0xCC;

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		return true;
	}

	//������������ϵ�
	bool set_hide_software_breakpoint(PVT_BREAK_POINT vmcallinfo)
	{
		int status = 0;
		VT_BREAK_POINT tmp_vmcallinfo = { 0 };

		if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
		{
			//��ȡ���ݿ��ܲ�����
			return false;
		}

		//��ȡĿ����̵������ַ
		unsigned __int64 physical_address = hv::get_physical_address(tmp_vmcallinfo.cr3, (PVOID)tmp_vmcallinfo.VirtualAddress);

		if (physical_address == NULL)
		{
			LogError("����������ַû��ӳ��������ַ");
			return false;
		}

		spinlock::lock(&eptWatchList_lock);

		//��ȡ���еļ���id
		int ID = hv::getIdleWatchID();

		if (ID == -1)
		{
			//û�п��ÿռ�
			spinlock::unlock(&eptWatchList_lock);
			return false;
		}


		//�ж��Ƿ��ҳ�ˣ���֧�ֿ�ҳ�¶ϣ�ֻ�����õ�ǰҳ��
		unsigned __int64 tmp = physical_address + tmp_vmcallinfo.Size;
		if (GET_PFN(tmp) != GET_PFN(physical_address))
			eptWatchList[ID].Size = 0x1000 - (physical_address & 0xfff);  //�����ҳ����ֻ�����õ�ǰҳ�棬���㵱ǰҳ������Ҫ���õ��ֽ�����С
		else
			eptWatchList[ID].Size = tmp_vmcallinfo.Size; //��Ҫ���öϵ���ֽ�����С

		eptWatchList[ID].cr3 = tmp_vmcallinfo.cr3;
		eptWatchList[ID].VirtualAddress = tmp_vmcallinfo.VirtualAddress;
		eptWatchList[ID].PhysicalAddress = physical_address;
		eptWatchList[ID].LoopUserMode = tmp_vmcallinfo.LoopUserMode;
		eptWatchList[ID].OriginalByte = tmp_vmcallinfo.OriginalBytes;
		eptWatchList[ID].Type = EPTW_READWRITE;

		eptWatchList[ID].Options = EPTO_VIRTUAL_BREAKPOINT;
		eptWatchList[ID].bpType = 3;

		eptWatchList[ID].inuse = 1;


		//Ϊÿ��cpu���ü���
		for (int i = 0; i < tmp_vmcallinfo.CPUCount; i++)
		{
			__vcpu* vcpu = &g_vmm_context.vcpu[i];
			if (hide_cc_breakpoint(*vcpu->ept_state, tmp_vmcallinfo, physical_address, EPTW_READWRITE))
			{
				status++;
			}
		}
		if (status == tmp_vmcallinfo.CPUCount)
		{
			tmp_vmcallinfo.watchid = ID;  //��¼���id��ж�ؼ��ӵ�ʱ����Ҫ
			tmp_vmcallinfo.PhysicalAddress = physical_address;

			if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
			{
				//д�����ݿ��ܲ�����
				spinlock::unlock(&eptWatchList_lock);
				return false;
			}

			invept_all_contexts_func(); //������ˢ��ȫ���߼���������eptp�Ĵ���
			spinlock::unlock(&eptWatchList_lock);

			return true;
		}
		spinlock::unlock(&eptWatchList_lock);
		return false;
	}

	//int3 hook
	bool cc_hook_function(__ept_state& ept_state, void* target_function/*���ҹ��ĺ�����ַ*/, void* proxy_function/*�º�����ַ*/, void** origin_function)
	{
		unsigned __int64 physical_address = MmGetPhysicalAddress(target_function).QuadPart;

		//
		// ���ú����Ƿ�����������ڴ���
		// ����ú����������ַΪ��
		// ˵���ú����������������ڴ���
		//
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				LogInfo("ҳ���ѹҹ�");

				__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, TRUE, sizeof(__ept_hooked_function_info));
				if (hooked_function_info == nullptr)
				{
					LogError("�ҹ������ṹû��Ԥ�ȷ�����ڴ�");
					return false;
				}

				//
				// If we are hooking code cave for second trampoline 
				// then origin function in null and we don't have to get pool for trampoline
				//
				if (origin_function != nullptr)
				{
					hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
					if (hooked_function_info->first_trampoline_address == nullptr)
					{
						pool_manager::release_pool(hooked_function_info);
						LogError("There is no pre-allocated pool for trampoline");
						return false;
					}
				}

				hooked_function_info->virtual_address = target_function;
				hooked_function_info->breakpoint_address = NULL;

				hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

				if (write_cc_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
				{
					if (hooked_function_info->first_trampoline_address != nullptr)
						pool_manager::release_pool(hooked_function_info->first_trampoline_address);
					pool_manager::release_pool(hooked_function_info);
					LogError("Hook failed");
					return false;
				}

				// Track all hooked functions within page
				InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

				return true;
			}
		}

		if (is_page_splitted(ept_state, physical_address) == false)
		{
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, true, sizeof(__ept_hooked_function_info));
		if (hooked_function_info == nullptr)
		{
			pool_manager::release_pool(hooked_page_info);
			LogError("hook����ʱԤ����Ļ����Ѻľ�");
			return false;
		}

		//
		// If we are hooking code cave for second trampoline 
		// then origin function in null and we don't have to get pool for trampoline
		//
		if (origin_function != nullptr)
		{
			hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
			if (hooked_function_info->first_trampoline_address == nullptr)
			{
				pool_manager::release_pool(hooked_page_info);
				pool_manager::release_pool(hooked_function_info);
				LogError("There is no pre-allocated pool for trampoline");
				return false;
			}
		}

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		//�ȸ�ԭҳΪ����ִ�� �ص�guest��ִ�оʹ���vmexit
		//����vmm�󽻻�α��ҳ
		hooked_page_info->entry_address->execute = 0;
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;

		hooked_page_info->original_entry = *target_page;
		hooked_page_info->changed_entry = *target_page;

		//α��ҳ���ö�д		
		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		//��α��ҳ����ȥ
		hooked_page_info->changed_entry.page_frame_number = hooked_page_info->pfn_of_fake_page_contents;

		RtlCopyMemory(&hooked_page_info->fake_page_contents, PAGE_ALIGN(target_function), PAGE_SIZE);

		hooked_function_info->virtual_address = target_function;
		hooked_function_info->breakpoint_address = NULL;

		hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

		//��ʼhook
		if (write_cc_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
		{
			if (hooked_function_info->first_trampoline_address != nullptr)
				pool_manager::release_pool(hooked_function_info->first_trampoline_address);
			pool_manager::release_pool(hooked_function_info);
			pool_manager::release_pool(hooked_page_info);
			LogError("Hook failed");
			return false;
		}

		//��¼hook�ĺ�����ҳ �Ա��պ��ͷ�
		// Track all hooked functions
		InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		invept_single_context_func(ept_state.ept_pointer->all);

		return true;
	}

	//#DB hook
	bool int1_hook_function(__ept_state& ept_state, void* target_function/*���ҹ��ĺ�����ַ*/, void* proxy_function/*�º�����ַ*/, void** origin_function)
	{
		unsigned __int64 physical_address = MmGetPhysicalAddress(target_function).QuadPart;

		//
		// ���ú����Ƿ�����������ڴ���
		// ����ú����������ַΪ��
		// ˵���ú����������������ڴ���
		//
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				LogInfo("ҳ���ѹҹ�");

				__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, TRUE, sizeof(__ept_hooked_function_info));
				if (hooked_function_info == nullptr)
				{
					LogError("�ҹ������ṹû��Ԥ�ȷ�����ڴ�");
					return false;
				}

				//
				// If we are hooking code cave for second trampoline 
				// then origin function in null and we don't have to get pool for trampoline
				//
				if (origin_function != nullptr)
				{
					hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
					if (hooked_function_info->first_trampoline_address == nullptr)
					{
						pool_manager::release_pool(hooked_function_info);
						LogError("There is no pre-allocated pool for trampoline");
						return false;
					}
				}

				hooked_function_info->virtual_address = target_function;
				hooked_function_info->breakpoint_address = NULL;

				hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

				if (write_int1_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
				{
					if (hooked_function_info->first_trampoline_address != nullptr)
						pool_manager::release_pool(hooked_function_info->first_trampoline_address);
					pool_manager::release_pool(hooked_function_info);
					LogError("Hook failed");
					return false;
				}

				// Track all hooked functions within page
				InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

				return true;
			}
		}

		if (is_page_splitted(ept_state, physical_address) == false)
		{
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, true, sizeof(__ept_hooked_function_info));
		if (hooked_function_info == nullptr)
		{
			pool_manager::release_pool(hooked_page_info);
			LogError("hook����ʱԤ����Ļ����Ѻľ�");
			return false;
		}

		//
		// If we are hooking code cave for second trampoline 
		// then origin function in null and we don't have to get pool for trampoline
		//
		if (origin_function != nullptr)
		{
			hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
			if (hooked_function_info->first_trampoline_address == nullptr)
			{
				pool_manager::release_pool(hooked_page_info);
				pool_manager::release_pool(hooked_function_info);
				LogError("There is no pre-allocated pool for trampoline");
				return false;
			}
		}

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		//�ȸ�ԭҳΪ����ִ�� �ص�guest��ִ�оʹ���vmexit
		//����vmm�󽻻�α��ҳ
		hooked_page_info->entry_address->execute = 0;
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;

		hooked_page_info->original_entry = *target_page;
		hooked_page_info->changed_entry = *target_page;

		//α��ҳ���ö�д		
		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		//��α��ҳ����ȥ
		hooked_page_info->changed_entry.page_frame_number = hooked_page_info->pfn_of_fake_page_contents;

		RtlCopyMemory(&hooked_page_info->fake_page_contents, PAGE_ALIGN(target_function), PAGE_SIZE);

		hooked_function_info->virtual_address = target_function;
		hooked_function_info->breakpoint_address = NULL;

		hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

		//��ʼhook
		if (write_int1_instruction_to_memory(hooked_function_info, target_function, proxy_function, origin_function) == false)
		{
			if (hooked_function_info->first_trampoline_address != nullptr)
				pool_manager::release_pool(hooked_function_info->first_trampoline_address);
			pool_manager::release_pool(hooked_function_info);
			pool_manager::release_pool(hooked_page_info);
			LogError("Hook failed");
			return false;
		}

		//��¼hook�ĺ�����ҳ �Ա��պ��ͷ�
		// Track all hooked functions
		InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		invept_single_context_func(ept_state.ept_pointer->all);

		return true;
	}

	/// <summary>
	/// Perfrom a hook
	/// </summary>
	/// <param name="target_address" > Address of function which we want to hook </param>
	/// <param name="proxy_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="(Optional) trampoline">Address of code cave which is located in 2gb range of target function (Use only if you need smaller trampoline)</param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_function(__ept_state& ept_state, void* target_function/*���ҹ��ĺ�����ַ*/, void* proxy_function/*�º�����ַ*/, void** origin_function)
	{
		unsigned __int64 physical_address = MmGetPhysicalAddress(target_function).QuadPart;

		//
		// ���ú����Ƿ�����������ڴ���
		// ����ú����������ַΪ��
		// ˵���ú����������������ڴ���
		//
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				LogInfo("ҳ���ѹҹ�");

				__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, TRUE, sizeof(__ept_hooked_function_info));
				if (hooked_function_info == nullptr)
				{
					LogError("�ҹ������ṹû��Ԥ�ȷ�����ڴ�");
					return false;
				}

				//
				// If we are hooking code cave for second trampoline 
				// then origin function in null and we don't have to get pool for trampoline
				//
				if (origin_function != nullptr)
				{
					hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
					if (hooked_function_info->first_trampoline_address == nullptr)
					{
						pool_manager::release_pool(hooked_function_info);
						LogError("There is no pre-allocated pool for trampoline");
						return false;
					}
				}

				hooked_function_info->virtual_address = target_function;

				hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

				if (hook_instruction_memory(ept_state, hooked_function_info, target_function, proxy_function, origin_function) == false)
				{
					if (hooked_function_info->first_trampoline_address != nullptr)
						pool_manager::release_pool(hooked_function_info->first_trampoline_address);
					pool_manager::release_pool(hooked_function_info);
					LogError("Hook failed");
					return false;
				}

				// Track all hooked functions within page
				InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

				return true;
			}
		}

		if (is_page_splitted(ept_state, physical_address) == false)
		{
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, true, sizeof(__ept_hooked_function_info));
		if (hooked_function_info == nullptr)
		{
			pool_manager::release_pool(hooked_page_info);
			LogError("There is no preallocated pool for hooked function info");
			return false;
		}

		//
		// If we are hooking code cave for second trampoline 
		// then origin function in null and we don't have to get pool for trampoline
		//
		if (origin_function != nullptr)
		{
			hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
			if (hooked_function_info->first_trampoline_address == nullptr)
			{
				pool_manager::release_pool(hooked_page_info);
				pool_manager::release_pool(hooked_function_info);
				LogError("There is no pre-allocated pool for trampoline");
				return false;
			}
		}

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		//�ȸ�ԭҳΪ����ִ�� �ص�guest��ִ�оʹ���vmexit
		//����vmm�󽻻�α��ҳ
		hooked_page_info->entry_address->execute = 0;
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;

		hooked_page_info->original_entry = *target_page;
		hooked_page_info->changed_entry = *target_page;

		//α��ҳ���ö�д		
		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		//��α��ҳ����ȥ
		hooked_page_info->changed_entry.page_frame_number = hooked_page_info->pfn_of_fake_page_contents;

		RtlCopyMemory(&hooked_page_info->fake_page_contents, PAGE_ALIGN(target_function), PAGE_SIZE);

		hooked_function_info->virtual_address = target_function;

		hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

		//��ʼhook
		if (hook_instruction_memory(ept_state, hooked_function_info, target_function, proxy_function, origin_function) == false)
		{
			if (hooked_function_info->first_trampoline_address != nullptr)
				pool_manager::release_pool(hooked_function_info->first_trampoline_address);
			pool_manager::release_pool(hooked_function_info);
			pool_manager::release_pool(hooked_page_info);
			LogError("Hook failed");
			return false;
		}

		hooked_page_info->Options = EPTO_HOOK_FUNCTION;

		//��¼hook�ĺ�����ҳ �Ա��պ��ͷ�
		// Track all hooked functions
		InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		invept_single_context_func(ept_state.ept_pointer->all);

		return true;
	}

	/// <summary>
	/// Unhook single function
	/// </summary>
	/// <param name="virtual_address"></param>
	/// <returns></returns>
	bool unhook_function(__ept_state& ept_state, unsigned __int64 virtual_address)
	{
		//
		// Check if function which we want to unhook exist in physical memory
		unsigned __int64 physical_address = MmGetPhysicalAddress((void*)virtual_address).QuadPart;
		if (physical_address == 0)
			return false;

		PLIST_ENTRY current_hooked_page = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current_hooked_page->Flink)
		{
			current_hooked_page = current_hooked_page->Flink;
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current_hooked_page, __ept_hooked_page_info, hooked_page_list);

			//
			// Check if function pfn is equal to pfn saved in hooked page info
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				PLIST_ENTRY current_hooked_function;
				current_hooked_function = &hooked_page_info->hooked_functions_list;

				while (&hooked_page_info->hooked_functions_list != current_hooked_function->Flink)
				{
					current_hooked_function = current_hooked_function->Flink;
					__ept_hooked_function_info* hooked_function_info = CONTAINING_RECORD(current_hooked_function, __ept_hooked_function_info, hooked_function_list);

					unsigned __int64 function_page_offset = MASK_EPT_PML1_OFFSET(virtual_address);

					//
					// Check if the address of function which we want to unhook is 
					// the same as address of function in hooked function info struct
					//
					if (function_page_offset == MASK_EPT_PML1_OFFSET(hooked_function_info->virtual_address))
					{
						// Restore overwritten data
						RtlCopyMemory(&hooked_function_info->fake_page_contents[function_page_offset], hooked_function_info->virtual_address, hooked_function_info->hook_size);

						// If hook uses two trampolines unhook second one
						if (hooked_function_info->second_trampoline_address != nullptr)
							unhook_function(ept_state, (unsigned __int64)hooked_function_info->second_trampoline_address);

						RemoveEntryList(current_hooked_function);

						if (hooked_function_info->first_trampoline_address != nullptr)
							pool_manager::release_pool(hooked_function_info->first_trampoline_address);
						pool_manager::release_pool(hooked_function_info);

						//
						// If there is no more function hooks free hooked page info struct
						if (hooked_page_info->hooked_functions_list.Flink == hooked_page_info->hooked_functions_list.Blink)
						{
							hooked_page_info->original_entry.execute = 1;
							swap_pml1_and_invalidate_tlb(ept_state, hooked_page_info->entry_address, hooked_page_info->original_entry, invept_single_context);

							RemoveEntryList(current_hooked_page);
							pool_manager::release_pool(hooked_page_info);
							return true;
						}

						invept_all_contexts_func();
						return true;
					}
				}
			}
		}
		return false;
	}

	/// <summary>
	/// Unhook all functions and invalidate tlb
	/// </summary>
	void unhook_all_functions(__ept_state& ept_state)
	{
		PLIST_ENTRY current_hooked_page = ept_state.hooked_page_list.Flink;
		while (&ept_state.hooked_page_list != current_hooked_page)
		{
			__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current_hooked_page, __ept_hooked_page_info, hooked_page_list);

			PLIST_ENTRY current_hooked_function;

			current_hooked_function = hooked_entry->hooked_functions_list.Flink;
			while (&hooked_entry->hooked_functions_list != current_hooked_function)
			{
				__ept_hooked_function_info* hooked_function_info = CONTAINING_RECORD(current_hooked_function, __ept_hooked_function_info, hooked_function_list);

				// If hook uses two trampolines unhook second one
				if (hooked_function_info->first_trampoline_address != nullptr)
					pool_manager::release_pool(hooked_function_info->first_trampoline_address);

				RemoveEntryList(current_hooked_function);

				current_hooked_function = current_hooked_function->Flink;

				pool_manager::release_pool(hooked_function_info);
			}

			// Restore original pte value
			// �ָ�ԭҳ��ִ������
			hooked_entry->original_entry.execute = 1;
			swap_pml1_and_invalidate_tlb(ept_state, hooked_entry->entry_address, hooked_entry->original_entry, invept_single_context);

			RemoveEntryList(current_hooked_page);

			current_hooked_page = current_hooked_page->Flink;

			pool_manager::release_pool(hooked_entry);
		}
	}

	void set_ept_watch(__ept_hooked_page_info* hooked_page_info, unsigned __int64 Type)
	{
		if (Type == EPTW_WRITE)  //����д
		{
			hooked_page_info->entry_address->write = 0;
		}
		//else if (Type == EPTW_READ) //���Ӷ�
		//{
		//	hooked_page_info->entry_address->read = 0;
		//}
		else if (Type == EPTW_READWRITE) //���Ӷ�д
		{
			hooked_page_info->entry_address->read = 0;
			hooked_page_info->entry_address->write = 0;
		}
		else if (Type == EPTW_EXECUTE)  //����ִ��
		{
			hooked_page_info->entry_address->execute = 0;
		}
		hooked_page_info->Options = EPTO_VIRTUAL_BREAKPOINT;
	}

	bool ept_watch_activate_internal(__ept_state& ept_state, unsigned __int64 physical_address, unsigned __int64 Type)
	{
		if (physical_address == NULL)
		{
			LogError("����������ڴ��������ڴ��в�����");
			return false;
		}

		//
		// ���ҳ���Ƿ���δ�ҹ�
		//
		PLIST_ENTRY current = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current->Flink)
		{
			current = current->Flink;
			//���б���ȡ���ҹ�ҳ
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			//�ж�Ŀ���ַ�Ƿ��Ǳ��ҹ���ҳ
			//���Ƚ�ҳ֡��
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				if (hooked_page_info->Options == EPTO_VIRTUAL_BREAKPOINT)
				{
					LogInfo("ҳ���ѹҹ�");

					set_ept_watch(hooked_page_info, Type);

					return true;
				}
			}
		}

		//�ж�2mb pde�Ƿ��Ѿ����зָ�
		if (is_page_splitted(ept_state, physical_address) == false)
		{
			//����ptҳ��
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			//��2MBҳ��ָ�Ϊ512��4KBҳ��
			if (split_pml2(g_vmm_context.mtrr_info.mtrrs, ept_state, split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		//�õ�Ŀ��ҳ
		__ept_pte* target_page = get_pml1_entry(ept_state, physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);  //��ȡguest����ҳ���ҳ֡��
		hooked_page_info->entry_address = target_page; //ept_pte

		set_ept_watch(hooked_page_info, Type);

		// Track all hooked pages
		InsertHeadList(&ept_state.hooked_page_list, &hooked_page_info->hooked_page_list);

		return true;
	}


	bool ept_watch_activate(VT_BREAK_POINT vmcallinfo, unsigned __int64 Type, int* outID, int& errorCode)
	{
		//��ȡguest�������ַ
		unsigned __int64 physical_address = hv::get_physical_address(vmcallinfo.cr3, (PVOID)vmcallinfo.VirtualAddress);

		if (physical_address == NULL)
		{
			LogError("����������ַû��ӳ��������ַ");
			errorCode = 100;
			return false;
		}

		int status = 0;

		spinlock::lock(&eptWatchList_lock);

		//��ȡ���еļ���id
		int ID = hv::getIdleWatchID();

		if (ID == -1)
		{
			//û�п��ÿռ�
			spinlock::unlock(&eptWatchList_lock);
			errorCode = 101;
			return false;
		}


		//�ж��Ƿ��ҳ�ˣ���֧�ֿ�ҳ�¶ϣ�ֻ�����õ�ǰҳ��
		unsigned __int64 tmp = physical_address + vmcallinfo.Size;
		if (GET_PFN(tmp) != GET_PFN(physical_address))
			eptWatchList[ID].Size = 0x1000 - (physical_address & 0xfff);  //�����ҳ����ֻ�����õ�ǰҳ�棬���㵱ǰҳ������Ҫ���õ��ֽ�����С
		else
			eptWatchList[ID].Size = vmcallinfo.Size; //��Ҫ���öϵ���ֽ�����С

		eptWatchList[ID].cr3 = vmcallinfo.cr3;
		eptWatchList[ID].PhysicalAddress = physical_address;
		eptWatchList[ID].LoopUserMode = vmcallinfo.LoopUserMode;
		eptWatchList[ID].Type = Type;

		eptWatchList[ID].Options = EPTO_VIRTUAL_BREAKPOINT;
		eptWatchList[ID].bpType = 1;

		eptWatchList[ID].inuse = 1;


		//Ϊÿ��cpu���ü���
		for (int i = 0; i < vmcallinfo.CPUCount; i++)
		{
			__vcpu* vcpu = &g_vmm_context.vcpu[i];
			if (ept::ept_watch_activate_internal(*vcpu->ept_state, physical_address, Type))
			{
				status++;
			}
		}
		if (status == vmcallinfo.CPUCount)
		{
			//һ�����������سɹ���
			*outID = ID;  //��¼���id��ж�ؼ��ӵ�ʱ����Ҫ			
			spinlock::unlock(&eptWatchList_lock);
			invept_all_contexts_func(); //������ˢ��ȫ���߼���������eptp�Ĵ���
			return true;
		}

		spinlock::unlock(&eptWatchList_lock);
		errorCode = 102;
		return false;
	}

	//ȡ������ҳ
	bool ept_watch_deactivate_internal(__ept_state& ept_state,
		unsigned __int64 VirtualAddress,
		unsigned __int64 physical_address,
		unsigned __int64 Type,
		int bpType,
		unsigned char OriginalByte,
		int has)
	{
		if (physical_address == NULL)
			return false;

		PLIST_ENTRY current_hooked_page = &ept_state.hooked_page_list;
		while (&ept_state.hooked_page_list != current_hooked_page->Flink)
		{
			current_hooked_page = current_hooked_page->Flink;
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current_hooked_page, __ept_hooked_page_info, hooked_page_list);

			//
			// ��麯�� pfn �Ƿ���ڹҹ�ҳ����Ϣ�б���� pfn
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				if (hooked_page_info->Options == EPTO_VIRTUAL_BREAKPOINT)
				{

					if (bpType == 3)
					{
						int offset = VirtualAddress & 0xFFF;
						hooked_page_info->fake_page_contents[offset] = OriginalByte;

						if (has == 0) //���hasΪ0��˵��û�д��������ļ��Ӷϵ㣬��ô���ǿ��Խ�ҳ���л���
						{
							hooked_page_info->original_entry.execute = 1;
							//����ԭҳ
							//hooked_page_info->entry_address->all = hooked_page_info->original_entry.all;

							swap_pml1_and_invalidate_tlb(ept_state,
								hooked_page_info->entry_address,
								hooked_page_info->original_entry,
								invept_single_context);
						}
					}
					else
					{
						if (Type == EPTW_WRITE)  //����д����
						{
							hooked_page_info->entry_address->write = 1;
						}
						//else if (Type == EPTW_READ)  //����������
						//{
						//	if (bpType == 3)  //int3
						//	{
						//		//����ԭҳ
						//		hooked_page_info->entry_address->all = hooked_page_info->original_entry.all;
						//	}
						//	hooked_page_info->entry_address->read = 1;
						//}
						else if (Type == EPTW_READWRITE) //������д����
						{
							hooked_page_info->entry_address->read = 1;
							hooked_page_info->entry_address->write = 1;
						}
						else if (Type == EPTW_EXECUTE)  //����ִ�м���
						{
							hooked_page_info->entry_address->execute = 1;
						}
					}

					if (has == 0) //���hasΪ0��˵��û�д��������ļ��Ӷϵ㣬��ô���ǿ��Խ�ҳ���л���
					{
						RemoveEntryList(current_hooked_page);
						pool_manager::release_pool(hooked_page_info);
					}
					return true;
				}
			}
		}
		return false;
	}


	int ept_watch_deactivate(VT_BREAK_POINT vmcallinfo, int ID)
	{
		int status = 0;
		int has = 0;
		spinlock::lock(&eptWatchList_lock);

		if (ID >= EPTWATCHLISTSIZE)
		{
			spinlock::unlock(&eptWatchList_lock);
			return 1;
		}

		if (eptWatchList[ID].inuse == 0)
		{
			spinlock::unlock(&eptWatchList_lock);
			return 2;
		}

		for (int i = 0; i < EPTWATCHLISTSIZE; i++)
		{
			if ((i != ID) && ept_isWatchPage(GET_PFN(eptWatchList[ID].PhysicalAddress), i))
			{
				has = 1;  //����ͬһҳ�������������Ӷϵ�
				if (eptWatchList[i].Type == eptWatchList[ID].Type)
				{
					has = 2;  //���ܳ���
					break;
				}
			}
		}

		//û�������ļ��Ӷϵ��ˣ����ڿ��԰�ҳ������
		if ((has != 2) || (eptWatchList[ID].bpType == 3))
		{
			//����ÿ��cpu
			for (int i = 0; i < vmcallinfo.CPUCount; i++)
			{
				__vcpu* vcpu = &g_vmm_context.vcpu[i];
				if (ept_watch_deactivate_internal(*vcpu->ept_state,
					eptWatchList[ID].VirtualAddress,
					eptWatchList[ID].PhysicalAddress,
					eptWatchList[ID].Type,
					eptWatchList[ID].bpType,
					eptWatchList[ID].OriginalByte,
					has))
				{
					status++;
				}
			}
			if (status == vmcallinfo.CPUCount)
			{
				invept_all_contexts_func(); //������ˢ��ȫ���߼���������eptp�Ĵ���			
			}
			else
			{
				spinlock::unlock(&eptWatchList_lock);
				return 3;
			}
		}
		else
		{
			//�����������Ķϵ㣬���Ի����ܰ�ҳȡ��
		}
		eptWatchList[ID] = { 0 };  //����ǰentry��inuse���Ϊδʹ��
		spinlock::unlock(&eptWatchList_lock);
		return 0;
	}

	//���ҳ�¼�������Ϣ
	void fillPageEventBasic(PageEventBasic* peb, guest_context* guest_registers)
	{
		peb->VirtualAddress = hv::vmread(GUEST_LINEAR_ADDRESS);
		peb->PhysicalAddress = hv::vmread(GUEST_PHYSICAL_ADDRESS);
		peb->CR3 = hv::vmread(GUEST_CR3);
		peb->FSBASE = hv::vmread(GUEST_FS_BASE);
		peb->GSBASE = hv::vmread(GUEST_GS_BASE);
		peb->FLAGS = hv::vmread(GUEST_RFLAGS);
		peb->RAX = guest_registers->rax;
		peb->RBX = guest_registers->rbx;
		peb->RCX = guest_registers->rcx;
		peb->RDX = guest_registers->rdx;
		peb->RSI = guest_registers->rsi;
		peb->RDI = guest_registers->rdi;
		peb->R8 = guest_registers->r8;
		peb->R9 = guest_registers->r9;
		peb->R10 = guest_registers->r10;
		peb->R11 = guest_registers->r11;
		peb->R12 = guest_registers->r12;
		peb->R13 = guest_registers->r13;
		peb->R14 = guest_registers->r14;
		peb->R15 = guest_registers->r15;
		peb->RBP = guest_registers->rbp;
		peb->RSP = hv::vmread(GUEST_RSP);
		peb->RIP = hv::vmread(GUEST_RIP);

		peb->DR0 = __readdr(0);
		peb->DR1 = __readdr(1);
		peb->DR2 = __readdr(2);
		peb->DR3 = __readdr(3);

		peb->DR6 = __readdr(6);
		peb->DR7 = hv::vmread(GUEST_DR7);
		peb->CS = hv::vmread(GUEST_CS_SELECTOR);
		peb->DS = hv::vmread(GUEST_DS_SELECTOR);
		peb->ES = hv::vmread(GUEST_ES_SELECTOR);
		peb->SS = hv::vmread(GUEST_SS_SELECTOR);
		peb->FS = hv::vmread(GUEST_FS_SELECTOR);
		peb->GS = hv::vmread(GUEST_GS_SELECTOR);
	}

	void RestoreEptPageProperties(__ept_hooked_page_info* hooked_page_info, int ID)
	{
		//��ԭeptҳ�����ԣ���guest����������ִ�У�������д
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;
		hooked_page_info->entry_address->execute = 1;
		hooked_page_info->ID = ID;
		hv::set_mtf(true);  //����mtf
	}

	//�ж��Ƿ��Ǽ��ӵĵ�ַ
	int ept_isWatchAddress(unsigned __int64 guest_physical_adddress, int ID)
	{
		return ((eptWatchList[ID].inuse) &&
			(
				(guest_physical_adddress >= eptWatchList[ID].PhysicalAddress) &&
				(guest_physical_adddress < eptWatchList[ID].PhysicalAddress + eptWatchList[ID].Size)
				)
			);
	}

	//�ж��Ƿ��Ǽ��ӵ�ҳ
	int ept_isWatchPage(unsigned __int64 pfn, int ID)
	{
		//�Ƚ�ҳ֡
		return ((eptWatchList[ID].inuse) && (GET_PFN(eptWatchList[ID].PhysicalAddress) == pfn));
	}

	int ept_getWatchID(unsigned __int64 guest_physical_adddress)
		/*
		 * returns -1 if not in a page being watched
		 * Note that there can be multiple active on the same page
		 * ������ڱ����ӵ�ҳ�����򷵻� -1
		 * ע��ͬһҳ���Ͽ����ж���
		 */
	{
		unsigned __int64 pfn = GET_PFN(guest_physical_adddress);  //��ȡҳ֡
		for (int i = 0; i < EPTWATCHLISTSIZE; i++)
			if (ept_isWatchPage(pfn, i))
				return i;

		return -1;
	}

	//����ϵ�����¼�
	bool ept_handleWatchEvent(__vcpu* vcpu,
		__ept_violation ept_violation,
		__ept_hooked_page_info* hooked_page_info,
		unsigned __int64 guest_physical_adddress,
		int& bpType)
	{

		//�ж��Ƿ��Ǳ����ӵ�ҳ��
		if (hooked_page_info->pfn_of_hooked_page == GET_PFN(guest_physical_adddress))
		{
			hooked_page_info->ID = -1;
			hooked_page_info->isBp = false;
			hooked_page_info->isInt3 = false;

			spinlock::lock(&eptWatchList_lock);
			int ID = ept_getWatchID(guest_physical_adddress);

			if (ID == -1)
			{
				spinlock::unlock(&eptWatchList_lock);
				return false;
			}

			if (eptWatchList[ID].bpType == 3) //int3
			{
				//�����������int3����ҳ����л�ҳ
				bpType = 3;
				hooked_page_info->ID = ID;
				spinlock::unlock(&eptWatchList_lock);
				return true;
			}



			//ȷ�������ķ���ԭ�����ͬһҳ�����ж�����ʣ�
			for (int i = ID; i < EPTWATCHLISTSIZE; i++)
			{
				if (ept_isWatchPage(GET_PFN(guest_physical_adddress), i)) //�ж��Ƿ��ڼ��ӵ�ҳ��
				{
					if (eptWatchList[i].Type == EPTW_WRITE)
					{
						if (ept_violation.write_access)  //ֻд
						{
							ID = i;

							if (ept_isWatchAddress(guest_physical_adddress, i)) //�ж��Ƿ��Ǽ��ӵĵ�ַ
								break;
						}
					}
					else if (eptWatchList[i].Type == EPTW_READWRITE)
					{
						if (ept_violation.read_access || ept_violation.write_access)  //����д
						{
							ID = i;
							if (ept_isWatchAddress(guest_physical_adddress, i))
								break;
						}
					}
					else
					{
						if (ept_violation.execute_access) //ִ��
						{
							ID = i;

							if (ept_isWatchAddress(guest_physical_adddress, i))
								break;
						}
					}
				}
			}


			//�ж��Ƿ������⻯�ϵ�
			if ((eptWatchList[ID].Options & EPTO_VIRTUAL_BREAKPOINT) &&
				(guest_physical_adddress >= eptWatchList[ID].PhysicalAddress) &&
				(guest_physical_adddress < eptWatchList[ID].PhysicalAddress + eptWatchList[ID].Size))
			{
				//if (eptWatchList[ID].bpType == 3) //int3
				//{
				//	//�����������int3��ַ����л�ҳ
				//	bpType = 3;
				//	hooked_page_info->ID = ID;

				//	cr3 guest_cr3;
				//	guest_cr3.flags = eptWatchList[ID].cr3;

				//	//ͬ��ԭҳ���ݵ�αҳ
				//	//if (PAGE_SIZE != hv::read_guest_virtual_memory(guest_cr3, PAGE_ALIGN(eptWatchList[ID].VirtualAddress), &hooked_page_info->fake_page_contents, PAGE_SIZE))
				//	//{
				//	//	//��ȡ���ݿ��ܲ�����
				//	//	spinlock::unlock(&eptWatchList_lock);
				//	//	return false;
				//	//}

				//	int offset = eptWatchList[ID].VirtualAddress & 0xFFF;  //���cc��λ��
				//	hooked_page_info->fake_page_contents[offset] = eptWatchList[ID].OriginalByte; //�ָ�ԭ�ֽ�
				//	spinlock::unlock(&eptWatchList_lock);
				//	return true;
				//}




				//This is the specific address that was being requested
				//if the current state has interrupts disabled or masked (cr8<>0) then skip (todo: step until it is)
				//���Ǳ�������ض���ַ�������ǰ״̬�ѽ��û������жϣ�cr8<>0������������todo����ִ��ֱ����ɣ�

				//Task Priority Register (CR8)
				//ϵͳ�������ʹ�� TPR �Ĵ�����ʱ��ֹ�����ȼ��жϣ��жϸ����ȼ�����
				//����ͨ����Ҫ��ֹ��������ȼ��жϵ�ֵ���ص� TPR ��ʵ�ֵġ����磬�� TPR ��ֵ����Ϊ 9 (1001b)
				//����ֹ���ȼ�Ϊ 9 ����͵������жϣ�ͬʱ����ʶ�����ȼ�Ϊ 10 ����ߵ������жϡ��� TPR ����Ϊ 0 �����������ⲿ�жϡ��� TPR ����Ϊ
				//15 (1111b) �ɽ��������ⲿ�жϡ�
				unsigned __int64 CR8 = __readcr8();
				rflags rflags;
				rflags.flags = hv::vmread(GUEST_RFLAGS);
				__vmx_interruptibility_state is = { hv::vmread(GUEST_INTERRUPTIBILITY_STATE) };
				int canBreak = (CR8 == 0) && (rflags.interrupt_enable_flag); //�ж��ж��Ƿ���
				canBreak = canBreak && ((is.all & (1 << 0)) == 0);

				if (canBreak) //�ж��ܷ�����ж�
				{
					int kernelmode = 0;

					//�жϴ���eptΥ��֮ǰ��ģʽ���ں˻����û�ģʽ
					kernelmode = hv::get_guest_cpl() == 0;

					unsigned __int64 newRIP = kernelmode ? 0 : eptWatchList[ID].LoopUserMode;

					if (newRIP)
					{
						hooked_page_info->isBp = true;
						//���ص�guest�������жϣ�ȷ���ܳɹ�ִ����GUEST_RIP����ָ��
						hv::vmwrite<unsigned __int64>(GUEST_INTERRUPTIBILITY_STATE, 1);  //blocking by STI ����
					}
				}
			}

			RestoreEptPageProperties(hooked_page_info, ID);
			spinlock::unlock(&eptWatchList_lock);
			return true;
		}
		return false;
	}
}