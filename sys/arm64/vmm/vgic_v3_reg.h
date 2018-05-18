#ifndef _VGIC_V3_REG_H_
#define _VGIC_V3_REG_H_

/* Interrupt Controller End of Interrupt Status Register */
#define ICH_EISR_EL2_STATUS_MASK	0xffff
#define ICH_EISR_EL2_EOI_NOT_HANDLED(lr)	((1 << lr) & ICH_EISR_EL2_STATUS_MASK)

/* Interrupt Controller Empty List Register Status Register */
#define ICH_ELRSR_EL2_STATUS_MASK	0xffff
#define ICH_ELRSR_EL2_LR_EMPTY(lr)	((1 << lr) & ICH_ELRSR_EL2_STATUS_MASK)

/* Interrupt Controller Hyp Control Register */
#define ICH_HCR_EL2_EOICOUNT_SHIFT	27
#define ICH_HCR_EL2_EOICOUNT_MASK	(0x1f << ICH_HCR_EL2_EOICOUNT_SHIFT)
#define ICH_HCR_EL2_TDIR		(1 << 14)	/* Trap non-secure EL1 writes to IC{C, V}_DIR_EL1 */
#define ICH_HCR_EL2_TSEI		(1 << 14) 	/* Trap System Error Interupts (SEI) to EL2 */
#define ICH_HCR_EL2_TALL1		(1 << 12) 	/* Trap non-secure EL1 accesses to IC{C, V}_* for Group 1 interrupts */
#define ICH_HCR_EL2_TALL0		(1 << 11) 	/* Trap non-secure EL1 accesses to IC{C, V}_* for Group 0 interrupts */
#define ICH_HCR_EL2_TC			(1 << 10) 	/* Trap non-secure EL1 accesses to common IC{C, V}_* registers */
#define ICH_HCR_EL2_VGRP1DIE		(1 << 7) 	/* VM Group 1 Disabled Interrupt Enable */
#define ICH_HCR_EL2_VGRP1EIE		(1 << 6)	/* VM Group 1 Enabled Interrupt Enable */
#define ICH_HCR_EL2_VGRP0DIE		(1 << 5) 	/* VM Group 0 Disabled Interrupt Enable */
#define ICH_HCR_EL2_VGRP0EIE		(1 << 4)	/* VM Group 0 Enabled Interrupt Enable */
#define ICH_HCR_EL2_NPIE		(1 << 3)	/* No Pending Interrupt Enable */
#define ICH_HCR_EL2_LRENPIE		(1 << 2)	/* List Register Entry Not Present Interrupt Enable */
#define ICH_HCR_EL2_UIE			(1 << 1)	/* Underflow Interrupt Enable */
#define ICH_HCR_EL2_En			(1 << 0)	/* Global enable for the virtual CPU interface */

/* Interrupt Controller List Registers */
#define ICH_LR_EL2_VINTID_MASK		0xffffffff
#define ICH_LR_EL2_PINTID_SHIFT		32
#define ICH_LR_EL2_PINTID_MASK		(0x3f << ICH_LR_EL2_PINTID_SHIFT)
#define ICH_LR_EL2_PRIO_SHIFT		48
#define ICH_LR_EL2_PRIO_MASK		(0xff << ICH_LR_EL2_PRIO_SHIFT)
#define ICH_LR_EL2_GROUP_1		(1 << 60) 	/* Virtual interrupt is Group 1 */
#define ICH_LR_EL2_HW			(1 << 61) 	/* Virtual interrupt has a corresponding physical interrupt */
/* The state of the virtual interrupt */
#define ICH_LR_EL2_STATE_SHIFT		62
#define ICH_LR_EL2_STATE_MASK		(0x3 << ICH_LR_EL2_STATE_SHIFT)
#define ICH_LR_EL2_STATE_INACTIVE	(0x0 << ICH_LR_EL2_STATE_SHIFT)
#define ICH_LR_EL2_STATE_PENDING	(0x1 << ICH_LR_EL2_STATE_SHIFT)
#define ICH_LR_EL2_STATE_ACTIVE		(0x2 << ICH_LR_EL2_STATE_SHIFT)
#define ICH_LR_EL2_STATE_PENDING_ACTIVE	(0x3 << ICH_LR_EL2_STATE_SHIFT)

/* Interrupt Controller Maintenance Interrupt State Register */
#define ICH_MISR_EL2_VGRP1D		(1 << 7)	/* vPE Group 1 Disabled */
#define ICH_MISR_EL2_VGRP1E		(1 << 6)	/* vPE Group 1 Enabled */
#define ICH_MISR_EL2_VGRP0D		(1 << 5)	/* vPE Group 0 Disabled */
#define ICH_MISR_EL2_VGRP0E		(1 << 4)	/* vPE Group 0 Enabled */
#define ICH_MISR_EL2_NP			(1 << 3)	/* No Pending */
#define ICH_MISR_EL2_LRENP		(1 << 2)	/* List Register Entry Not Present */
#define ICH_MISR_EL2_U			(1 << 1)	/* Underflow */
#define ICH_MISR_EL2_EOI		(1 << 0)	/* End Of Interrupt */

/* Interrupt Controller Virtual Machine Control Register */
#define ICH_VMCR_EL2_VPMR_SHIFT		24
#define ICH_VMCR_EL2_VPMR_MASK		(0xff << ICH_VMCR_EL2_VPMR_SHIFT)
#define  ICH_VMCR_EL2_VPMR_PRIO_LOWEST	(0xff << ICH_VMCR_EL2_VPMR_SHIFT)
#define  ICH_VMCR_EL2_VPMR_PRIO_HIGHEST	(0x00 << ICH_VMCR_EL2_VPMR_SHIFT)
#define ICH_VMCR_EL2_VBPR0_SHIFT	21
#define ICH_VMCR_EL2_VBPR0_MASK		(0x7 << ICH_VMCR_EL2_VBPR0_SHIFT)
#define  ICH_VMCR_EL2_VBPR0_NO_PREEMPTION \
    (0x7 << ICH_VMCR_EL2_VBPR0_SHIFT)
#define ICH_VMCR_EL2_VBPR1_SHIFT	18
#define ICH_VMCR_EL2_VBPR1_MASK		(0x7 << ICH_VMCR_EL2_VBPR1_SHIFT)
#define  ICH_VMCR_EL2_VBPR1_NO_PREEMPTION \
    (0x7 << ICH_VMCR_EL2_VBPR1_SHIFT)
#define ICH_VMCR_EL2_VEOIM		(1 << 9)	/* Virtual EOI mode */
#define ICH_VMCR_EL2_VCBPR		(1 << 4)	/* Virtual Common binary Point Register */
#define ICH_VMCR_EL2_VFIQEN		(1 << 3)	/* Virtual FIQ enable */
#define ICH_VMCR_EL2_VACKCTL		(1 << 2)	/* Virtual AckCtl */
#define ICH_VMCR_EL2_VENG1		(1 << 1)	/* Virtual Group 1 Interrupt Enable */
#define ICH_VMCR_EL2_VENG0		(1 << 0)	/* Virtual Group 0 Interrupt Enable */

/* Interrupt Controller VGIC Type Register */
#define ICH_VTR_EL2_PRIBITS_SHIFT	29
#define ICH_VTR_EL2_PRIBITS_MASK	(0x7 << ICH_VTR_EL2_PRIBITS_SHIFT)
#define	ICH_VTR_EL2_PRIBITS(x)		\
    ((((x) & ICH_VTR_EL2_PRIBITS_MASK) >> ICH_VTR_EL2_PRIBITS_SHIFT) + 1)
#define ICH_VTR_EL2_PREBITS_SHIFT	26
#define ICH_VTR_EL2_PREBITS_MASK	(0x7 << ICH_VTR_EL2_PREBITS_SHIFT)
#define	ICH_VTR_EL2_PREBITS(x)		\
		(((x) & ICH_VTR_EL2_PREBITS_MASK) >> ICH_VTR_EL2_PREBITS_SHIFT)
#define ICH_VTR_EL2_SEIS		(1 << 22)	/* System Error Interrupt (SEI) Support */
#define ICH_VTR_EL2_A3V			(1 << 21)	/* Affinity 3 Valid */
#define ICH_VTR_EL2_NV4			(1 << 20)	/* Direct injection of virtual interrupts. RES1 for GICv3 */
#define ICH_VTR_EL2_TDS			(1 << 19)	/* Implementation supports ICH_HCR_EL2.TDIR */
#define ICH_VTR_EL2_LISTREGS_MASK	0x1f
/*
 * ICH_VTR_EL2.ListRegs holds the number of list registers, minus one. Add one
 * to get the actual number of list registers.
 */
#define	ICH_VTR_EL2_LISTREGS(x)		\
		(((x) & ICH_VTR_EL2_LISTREGS_MASK) + 1)

#endif /* !_VGIC_V3_REG_H_ */
