#ifndef _ASM_X86_AMD_PSP_H_
#define _ASM_X86_AMD_PSP_H_

#include <xen/types.h>

/*
 * The PSP DRTM mailbox. GRUB uses it to set up a Trusted Memory Region over
 * the memory it launches into, SKL uses it to extend the OS loader digest and
 * to issue DRTM_CMD_LAUNCH, and Xen uses it to release that TMR once its own
 * IOMMU is programmed and to lock the DRTM TPM localities on the way out.
 *
 * C2PMSG_72 carries a command and returns a status in one 32-bit register:
 *
 *   31    Ready
 *   27:24 TMR index
 *   23:16 Command
 *   15:0  Status
 */
#define DRTM_MBOX_READY_MASK        0x80000000
#define DRTM_MBOX_TMR_INDEX_MASK    0x0F000000
#define DRTM_MBOX_CMD_MASK          0x00FF0000
#define DRTM_MBOX_STATUS_MASK       0x0000FFFF

#define DRTM_MBOX_CMD_SHIFT         16
#define DRTM_MBOX_TMR_INDEX_SHIFT   24

/* Status values, returned in bits 15:0 of C2PMSG_72. */
#define DRTM_NO_ERROR                   0x0000
#define DRTM_NOT_SUPPORTED              0x0001
#define DRTM_LAUNCH_ERROR               0x0002
#define DRTM_TMR_SETUP_FAILED_ERROR     0x0003
#define DRTM_TMR_DESTROY_FAILED_ERROR   0x0004
#define DRTM_GET_TCG_LOGS_FAILED_ERROR  0x0007
#define DRTM_OUT_OF_RESOURCES_ERROR     0x0008
#define DRTM_GENERIC_ERROR              0x0009
#define DRTM_INVALID_SERVICE_ID_ERROR   0x000A
#define DRTM_MEMORY_UNALIGNED_ERROR     0x000B
#define DRTM_MINIMUM_SIZE_ERROR         0x000C
#define DRTM_GET_TMR_DESCRIPTOR_FAILED  0x000D
#define DRTM_EXTEND_OSSL_DIGEST_FAILED  0x000E
#define DRTM_SETUP_NOT_ALLOWED          0x000F
#define DRTM_GET_IVRS_TABLE_FAILED      0x0010

/*
 * The commands Xen issues. The bootloader and SKL drive the rest of the
 * interface, see grub-core/loader/slaunch/psp.c and SKL's psp.c.
 */
#define DRTM_CMD_TMR_RELEASE            0x3
#define DRTM_CMD_TPM_LOCALITY_ACCESS    0x8

/* GRUB sets up one TMR, at index 0. */
#define DRTM_TMR_INDEX_0                0

/*
 * Probe for the PSP, then locate and map C2PMSG_72 and wait for the PSP to
 * accept commands.
 */
void slaunch_psp_setup(void);

/*
 * Whether the probe in slaunch_psp_setup() found a PSP, and so whether a TMR is
 * live. Stays true when the mailbox turns out to be unreachable, so that the
 * caller fails rather than continuing with the TMR in place.
 */
bool slaunch_psp_active(void);

/* Release TMR 0, dropping the DMA protection GRUB set up over Xen. */
bool slaunch_psp_tmr_release(void);

/* Lock the DRTM TPM localities and drop the mapping. */
void slaunch_psp_finalize(void);

#endif /* _ASM_X86_AMD_PSP_H_ */
