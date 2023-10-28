/* SPDX-License-Identifier: GPL-2.0-only */

/*
 *  Copyright (c) 2025 Apertus Solutions, LLC
 *  Copyright (c) 2025 Oracle and/or its affiliates.
 *  Copyright (c) 2025 3mdeb Sp. z o.o
 *
 *  Secure Launch Resource Table definitions.  This table is passed to Xen by
 *  a bootloader and contains information about pre-DRTM state necessary to
 *  restore hardware configuration, where to find TPM event log, how to call
 *  back into the bootloader (for EFI case) and what needs to be measured by
 *  Xen.  In other words, this is similar to MBI in Multiboot Specification.
 *
 *  Specification:
 *    https://trenchboot.org/specifications/Secure_Launch/
 */

#ifndef XEN_SLR_TABLE_H
#define XEN_SLR_TABLE_H

#include <xen/types.h>

/* SLR table header values */
#define SLR_TABLE_MAGIC         0x4452544d
#define SLR_TABLE_REVISION      1

/* Current revisions for the policy and UEFI config */
#define SLR_POLICY_REVISION         1
#define SLR_UEFI_CONFIG_REVISION    1

/* SLR defined architectures */
#define SLR_INTEL_TXT   1
#define SLR_AMD_SKINIT  2

/* SLR defined bootloaders */
#define SLR_BOOTLOADER_INVALID  0
#define SLR_BOOTLOADER_GRUB     1

/* Log formats */
#define SLR_DRTM_TPM12_LOG      1
#define SLR_DRTM_TPM20_LOG      2

/* DRTM Policy Entry Flags */
#define SLR_POLICY_FLAG_MEASURED    0x1
#define SLR_POLICY_IMPLICIT_SIZE    0x2

/* Array Lengths */
#define TPM_EVENT_INFO_LENGTH       32
#define TXT_VARIABLE_MTRRS_LENGTH   32

/* Tags */
#define SLR_ENTRY_INVALID       0x0000
#define SLR_ENTRY_DL_INFO       0x0001
#define SLR_ENTRY_LOG_INFO      0x0002
#define SLR_ENTRY_DRTM_POLICY   0x0003
#define SLR_ENTRY_INTEL_INFO    0x0004
#define SLR_ENTRY_AMD_INFO      0x0005
#define SLR_ENTRY_ARM_INFO      0x0006
#define SLR_ENTRY_UEFI_INFO     0x0007
#define SLR_ENTRY_UEFI_CONFIG   0x0008
#define SLR_ENTRY_END           0xffff

/* Entity Types */
#define SLR_ET_UNSPECIFIED        0x0000
#define SLR_ET_SLRT               0x0001
#define SLR_ET_BOOT_PARAMS        0x0002
#define SLR_ET_SETUP_DATA         0x0003
#define SLR_ET_CMDLINE            0x0004
#define SLR_ET_UEFI_MEMMAP        0x0005
#define SLR_ET_RAMDISK            0x0006
#define SLR_ET_MULTIBOOT2_INFO    0x0007
#define SLR_ET_MULTIBOOT2_MODULE  0x0008
#define SLR_ET_TXT_OS2MLE         0x0010
#define SLR_ET_UNUSED             0xffff

/*
 * Primary SLR Table Header
 */
struct slr_table
{
    uint32_t magic;
    uint16_t revision;
    uint16_t architecture;
    uint32_t size;
    uint32_t max_size;
    /* entries[] */
} __packed;

/*
 * Common SLRT Table Header
 */
struct slr_entry_hdr
{
    uint32_t tag;
    uint32_t size;
} __packed;

/*
 * Boot loader context
 */
struct slr_bl_context
{
    uint16_t bootloader;
    uint16_t reserved[3];
    uint64_t context;
} __packed;

/*
 * Prototype of a function pointed to by slr_entry_dl_info::dl_handler.
 */
typedef void (*dl_handler_func)(const struct slr_bl_context *bl_context);

/*
 * DRTM Dynamic Launch Configuration
 */
struct slr_entry_dl_info
{
    struct slr_entry_hdr hdr;
    uint64_t dce_size;
    uint64_t dce_base;
    uint64_t dlme_size;
    uint64_t dlme_base;
    uint64_t dlme_entry;
    struct slr_bl_context bl_context;
    uint64_t dl_handler;
} __packed;

/*
 * TPM Log Information
 */
struct slr_entry_log_info
{
    struct slr_entry_hdr hdr;
    uint16_t format;
    uint16_t reserved;
    uint32_t size;
    uint64_t addr;
} __packed;

/*
 * DRTM Measurement Entry
 */
struct slr_policy_entry
{
    uint16_t pcr;
    uint16_t entity_type;
    uint16_t flags;
    uint16_t reserved;
    uint64_t size;
    uint64_t entity;
    char evt_info[TPM_EVENT_INFO_LENGTH];
} __packed;

/*
 * DRTM Measurement Policy
 */
struct slr_entry_policy
{
    struct slr_entry_hdr hdr;
    uint16_t reserved[2];
    uint16_t revision;
    uint16_t nr_entries;
    struct slr_policy_entry policy_entries[];
} __packed;

/*
 * Secure Launch defined MTRR saving structures
 */
struct slr_txt_mtrr_pair
{
    uint64_t mtrr_physbase;
    uint64_t mtrr_physmask;
} __packed;

struct slr_txt_mtrr_state
{
    uint64_t default_mem_type;
    uint64_t mtrr_vcnt;
    struct slr_txt_mtrr_pair mtrr_pair[TXT_VARIABLE_MTRRS_LENGTH];
} __packed;

/*
 * Intel TXT Info table
 */
struct slr_entry_intel_info
{
    struct slr_entry_hdr hdr;
    uint64_t boot_params_base;
    uint64_t txt_heap;
    uint64_t saved_misc_enable_msr;
    struct slr_txt_mtrr_state saved_bsp_mtrrs;
} __packed;

/*
 * AMD SKINIT Info table
 */
struct slr_entry_amd_info
{
    struct slr_entry_hdr hdr;
    uint64_t next;
    uint32_t type;
    uint32_t len;
    uint64_t slrt_size;
    uint64_t slrt_base;
    uint64_t boot_params_base;
    uint16_t psp_version;
    uint16_t reserved[3];
} __packed;

/*
 * UEFI config measurement entry
 */
struct slr_uefi_cfg_entry
{
    uint16_t pcr;
    uint16_t reserved;
    uint32_t size;
    uint64_t cfg; /* address or value */
    char evt_info[TPM_EVENT_INFO_LENGTH];
} __packed;

struct slr_entry_uefi_config
{
    struct slr_entry_hdr hdr;
    uint16_t reserved[2];
    uint16_t revision;
    uint16_t nr_entries;
    struct slr_uefi_cfg_entry uefi_cfg_entries[];
} __packed;

static inline const void *
slr_end_of_entries(const struct slr_table *table)
{
    return (const void *)table + table->size;
}

static inline const struct slr_entry_hdr *
slr_next_entry(const struct slr_table *table, const struct slr_entry_hdr *curr)
{
    const struct slr_entry_hdr *next = (void *)curr + curr->size;

    if ( (void *)next + sizeof(*next) > slr_end_of_entries(table) )
        return NULL;
    if ( next->tag == SLR_ENTRY_END )
        return NULL;
    if ( (void *)next + next->size > slr_end_of_entries(table) )
        return NULL;

    return next;
}

static inline const struct slr_entry_hdr *
slr_next_entry_by_tag(const struct slr_table *table,
                      const struct slr_entry_hdr *entry,
                      uint16_t tag)
{
    if ( !entry ) /* Start from the beginning */
        entry = (void *)table + sizeof(*table);

    for ( ; ; )
    {
        if ( entry->tag == tag )
            return entry;

        entry = slr_next_entry(table, entry);
        if ( !entry )
            return NULL;
    }

    return NULL;
}

#endif /* XEN_SLR_TABLE_H */
