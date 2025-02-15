#pragma once

#ifndef _HYPERVISOR_GATEWAY_H
#define _HYPERVISOR_GATEWAY_H

namespace hvgt
{
	/// <summary>
	/// Turn off virtual machine
	/// </summary>
	void vmoff();

	/// <summary>
	/// Invalidates mappings in the translation lookaside buffers (TLBs) 
	/// and paging-structure caches that were derived from extended page tables (EPT)
	/// </summary>
	/// <param name="invept_all"> If true invalidates all contexts otherway invalidate only single context (currently hv doesn't use more than 1 context)</param>
	void invept(bool invept_all);

	/// <summary>
	/// Set/Unset presence of hypervisor
	/// </summary>
	/// <param name="value"> If false, hypervisor is not visible via cpuid interface, If true, it become visible</param>
	void hypervisor_visible(bool value);

	/// <summary>
	/// Unhook all pages and invalidate tlb
	/// </summary>
	/// <returns> status </returns>
	bool ept_unhook();

	/// <summary>
	/// Unhook single page and invalidate tlb
	/// </summary>
	/// <param name="page_physcial_address"></param>
	/// <returns> status </returns>
	bool ept_unhook(void* function_address);

	/// <summary>
	/// Hook function via ept and invalidates mappings
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* proxy_function, void** origin_function);

	//�㲥�������߼�������
	bool vmcall(PVOID vmcallinfo);

	/// <summary>
	/// Check if we can communicate with hypervisor
	/// </summary>
	/// <returns> status </returns>
	bool test_vmcall();

	/// <summary>
	/// Send irp with information to allocate memory
	/// </summary>
	/// <returns> status </returns>
	bool send_irp_perform_allocation();

	//��eptαҳ�ڴ�
	bool read_ept_fake_page_memory(void* target_address, void* buffer, unsigned __int64 buffer_size);

	//��ȡ��������ϵ�
	bool get_hide_software_breakpoint(void* target_address, void* buffer, unsigned __int64 buffer_size);

	//������������ϵ�
	bool set_hide_software_breakpoint(MDL_MAP* map_table, void* buffer, unsigned __int64 buffer_size);
}

#endif // !_HYPERVISOR_GATEWAY_H
