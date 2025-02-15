#pragma once

#ifndef _VMM_H
#define _VMM_H

/// <summary>
/// Initialize and launch vmm
/// </summary>
/// <returns> status </returns>
bool vmm_init();

/// <summary>
/// Deallocate all structures
/// </summary>
void free_vmm_context();

//����hostҳ��
void create_host_page_tables();

//����vcpu�ṹ�ڴ�
bool init_vcpu(__vcpu* vcpu);

#endif // !_VMM_H
