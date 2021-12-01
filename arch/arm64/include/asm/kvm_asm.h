/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

#include <asm/virt.h>

#define ARM_EXCEPTION_IRQ	  0
#define ARM_EXCEPTION_TRAP	  1

#define KVM_ARM64_DEBUG_DIRTY_SHIFT	0
#define KVM_ARM64_DEBUG_DIRTY		(1 << KVM_ARM64_DEBUG_DIRTY_SHIFT)

#ifndef __ASSEMBLY__
struct kvm;
struct kvm_vcpu;

extern char __kvm_hyp_init[];
extern char __kvm_hyp_init_end[];

extern char __kvm_hyp_vector[];

#define	__kvm_hyp_code_start	__hyp_text_start
#define	__kvm_hyp_code_end	__hyp_text_end

extern void __kvm_flush_vm_context(void);
extern void __kvm_tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa);

extern int __kvm_vcpu_run(struct kvm_vcpu *vcpu);

extern u64 __vgic_v3_get_ich_vtr_el2(void);

extern char __save_vgic_v2_state[];
extern char __restore_vgic_v2_state[];
extern char __save_vgic_v3_state[];
extern char __restore_vgic_v3_state[];

#endif

#endif /* __ARM_KVM_ASM_H__ */
