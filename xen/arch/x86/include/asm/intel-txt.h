/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Intel TXT is an implementation of DRTM in CPUs made by Intel (although CPU
 * alone isn't enough, chipset must support TXT as well).
 *
 * Overview:
 *   https://www.intel.com/content/www/us/en/support/articles/000025873/processors.html
 * Software Development Guide (SDG):
 *   https://www.intel.com/content/www/us/en/content-details/315168/
 */

#ifndef X86_INTEL_TXT_H
#define X86_INTEL_TXT_H

/*
 * TXT configuration registers (offsets from TXT_{PUB, PRIV}_CONFIG_REGS_BASE)
 */
#define TXT_PUB_CONFIG_REGS_BASE        0xfed30000U
#define TXT_PRIV_CONFIG_REGS_BASE       0xfed20000U

/*
 * The same set of registers is exposed twice (with different permissions) and
 * they are allocated continuously with page alignment.
 */
#define TXT_CONFIG_SPACE_SIZE \
    (TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE)

/* Offsets from pub/priv config space. */
#define TXTCR_STS                       0x0000
#define TXTCR_ESTS                      0x0008
#define TXTCR_ERRORCODE                 0x0030
#define TXTCR_CMD_RESET                 0x0038
#define TXTCR_CMD_CLOSE_PRIVATE         0x0048
#define TXTCR_DIDVID                    0x0110
#define TXTCR_VER_EMIF                  0x0200
#define TXTCR_CMD_UNLOCK_MEM_CONFIG     0x0218
#define TXTCR_SINIT_BASE                0x0270
#define TXTCR_SINIT_SIZE                0x0278
#define TXTCR_MLE_JOIN                  0x0290
#define TXTCR_HEAP_BASE                 0x0300
#define TXTCR_HEAP_SIZE                 0x0308
#define TXTCR_SCRATCHPAD                0x0378
#define TXTCR_CMD_OPEN_LOCALITY1        0x0380
#define TXTCR_CMD_CLOSE_LOCALITY1       0x0388
#define TXTCR_CMD_OPEN_LOCALITY2        0x0390
#define TXTCR_CMD_CLOSE_LOCALITY2       0x0398
#define TXTCR_CMD_SECRETS               0x08e0
#define TXTCR_CMD_NO_SECRETS            0x08e8
#define TXTCR_E2STS                     0x08f0

/*
 * Secure Launch Defined Error Codes used in MLE-initiated TXT resets.
 *
 * TXT Specification
 * Appendix I ACM Error Codes
 */
#define SLAUNCH_ERROR_INTEGER_OVERFLOW  0xc0008001U
#define SLAUNCH_ERROR_HI_PMR_BASE       0xc0008002U
#define SLAUNCH_ERROR_LO_PMR_BASE       0xc0008003U
#define SLAUNCH_ERROR_LO_PMR_SIZE       0xc0008004U
#define SLAUNCH_ERROR_LO_PMR_MLE        0xc0008005U
#define SLAUNCH_ERROR_BUFFER_BEYOND_PMR 0xc0008006U
#define SLAUNCH_ERROR_HEAP_BAD_OS2MLE   0xc0008007U
#define SLAUNCH_ERROR_HEAP_BAD_OS2SINIT 0xc0008008U
#define SLAUNCH_ERROR_NO_VENDOR_INFO    0xc0008009U
#define SLAUNCH_ERROR_BAD_VENDOR_INFO   0xc000800AU
#define SLAUNCH_ERROR_BAD_SLRT_ADDRESS  0xc000800BU

#ifndef __ASSEMBLER__

/* Need to differentiate between pre- and post paging enabled. */
#ifdef __EARLY_SLAUNCH__
#include <xen/macros.h>
#define _txt(x) _p(x)
#else
#include <xen/types.h>
#include <asm/page.h>   /* __va() */
#define _txt(x) __va(x)
#endif

/*
 * Always use private space as some of registers are either read-only or not
 * present in public space.
 */
static inline uint64_t txt_read(unsigned int reg_no)
{
    volatile uint64_t *reg = _txt(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
    return *reg;
}

static inline void txt_write(unsigned int reg_no, uint64_t val)
{
    volatile uint64_t *reg = _txt(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
    *reg = val;
}

static inline void noreturn txt_reset(uint32_t error)
{
    txt_write(TXTCR_ERRORCODE, error);
    txt_write(TXTCR_CMD_NO_SECRETS, 1);
    txt_write(TXTCR_CMD_UNLOCK_MEM_CONFIG, 1);
    /*
     * Ignoring the result as this serves as a TXT register barrier after
     * writing to TXTCR_CMD_UNLOCK_MEM_CONFIG. Must be done to ensure that any
     * future chipset operations see the write.
     */
    txt_read(TXTCR_ESTS);
    txt_write(TXTCR_CMD_RESET, 1);

    while (true)
    {
        /*
         * This is halt() from <asm/system.h>.  Can't include the file as it
         * breaks early code compilation.
         */
        asm volatile ( "hlt" : : : "memory" );
    }
    unreachable();
}

/*
 * Secure Launch defined OS/MLE TXT Heap table
 */
struct txt_os_mle_data {
    uint32_t version;
    uint32_t reserved;
    uint64_t slrt;
    uint64_t txt_info;
    uint32_t ap_wake_block;
    uint32_t ap_wake_block_size;
    uint8_t mle_scratch[64];
} __packed;

/*
 * TXT specification defined BIOS data TXT Heap table
 */
struct txt_bios_data {
    uint32_t version; /* Currently 5 for TPM 1.2 and 6 for TPM 2.0 */
    uint32_t bios_sinit_size;
    uint64_t reserved1;
    uint64_t reserved2;
    uint32_t num_logical_procs;
    /* Versions >= 3 && < 5 */
    uint32_t sinit_flags;
    /* Versions >= 5 with updates in version 6 */
    uint32_t mle_flags;
    /* Versions >= 4 */
    /* Ext Data Elements */
} __packed;

/*
 * TXT specification defined OS/SINIT TXT Heap table
 */
struct txt_os_sinit_data {
    uint32_t version;       /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
    uint32_t flags;         /* Reserved in version 6 */
    uint64_t mle_ptab;
    uint64_t mle_size;
    uint64_t mle_hdr_base;
    uint64_t vtd_pmr_lo_base;
    uint64_t vtd_pmr_lo_size;
    uint64_t vtd_pmr_hi_base;
    uint64_t vtd_pmr_hi_size;
    uint64_t lcp_po_base;
    uint64_t lcp_po_size;
    uint32_t capabilities;
    /* Version = 5 */
    uint64_t efi_rsdt_ptr;  /* RSD*P* in versions >= 6 */
    /* Versions >= 6 */
    /* Ext Data Elements */
} __packed;

/*
 * TXT specification defined SINIT/MLE TXT Heap table
 */
struct txt_sinit_mle_data {
    uint32_t version;  /* Current values are 6 through 9 */
    /* Versions <= 8, fields until lcp_policy_control must be 0 for >= 9 */
    uint8_t bios_acm_id[20];
    uint32_t edx_senter_flags;
    uint64_t mseg_valid;
    uint8_t sinit_hash[20];
    uint8_t mle_hash[20];
    uint8_t stm_hash[20];
    uint8_t lcp_policy_hash[20];
    uint32_t lcp_policy_control;
    /* Versions >= 7 */
    uint32_t rlp_wakeup_addr;
    uint32_t reserved;
    uint32_t num_of_sinit_mdrs;
    uint32_t sinit_mdrs_table_offset;
    uint32_t sinit_vtd_dmar_table_size;
    uint32_t sinit_vtd_dmar_table_offset;
    /* Versions >= 8 */
    uint32_t processor_scrtm_status;
    /* Versions >= 9 */
    /* Ext Data Elements */
} __packed;

/*
 * Functions to extract data from the Intel TXT Heap Memory.
 *
 * The layout of the heap is dictated by TXT. It's a set of variable-sized
 * tables that appear in pre-defined order:
 *
 *   +------------------------------------+
 *   | Size of Bios Data table (uint64_t) |
 *   +------------------------------------+
 *   | Bios Data table                    |
 *   +------------------------------------+
 *   | Size of OS MLE table (uint64_t)    |
 *   +------------------------------------+
 *   | OS MLE table                       |
 *   +--------------------------------    +
 *   | Size of OS SINIT table (uint64_t)  |
 *   +------------------------------------+
 *   | OS SINIT table                     |
 *   +------------------------------------+
 *   | Size of SINIT MLE table (uint64_t) |
 *   +------------------------------------+
 *   | SINIT MLE table                    |
 *   +------------------------------------+
 *
 * NOTE: the table size fields include the 8 byte size field itself.
 *
 * NOTE: despite SDG mentioning 8-byte alignment, at least some BIOS ACM modules
 *       were observed to violate this requirement for Bios Data table, so not
 *       enforcing any alignment.
 */
enum {
    TXT_BIOS,
    TXT_OS2MLE,
    TXT_OS2SINIT,
    TXT_SINIT2MLE,
};
static inline uint64_t txt_size(const void *heap, int table_index)
{
    int i;
    for (i = 0; i < table_index; ++i)
        heap += *(const uint64_t *)heap;
    return *(const uint64_t *)heap - sizeof(uint64_t);
}
static inline void *txt_start(void *heap, int table_index)
{
    int i;
    for (i = 0; i < table_index; ++i)
        heap += *(const uint64_t *)heap;
    return heap + sizeof(uint64_t);
}

static inline void *txt_init(void)
{
    void *txt_heap;

    /* Clear the TXT error register for a clean start of the day. */
    txt_write(TXTCR_ERRORCODE, 0);

    txt_heap = _p(txt_read(TXTCR_HEAP_BASE));

    if ( txt_size(txt_heap, TXT_OS2MLE) < sizeof(struct txt_os_mle_data) )
        txt_reset(SLAUNCH_ERROR_HEAP_BAD_OS2MLE);
    if ( txt_size(txt_heap, TXT_OS2SINIT) < sizeof(struct txt_os_sinit_data) )
        txt_reset(SLAUNCH_ERROR_HEAP_BAD_OS2SINIT);

    return txt_heap;
}

#endif /* !__ASSEMBLER__ */

#endif /* X86_INTEL_TXT_H */
