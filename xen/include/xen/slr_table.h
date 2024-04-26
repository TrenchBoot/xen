/* SPDX-License-Identifier: GPL-3.0 */

/*
 *  Copyright (C) 2023  Oracle and/or its affiliates.
 *
 *  Secure Launch Resource Table definitions
 */

#ifndef _SLR_TABLE_H
#define _SLR_TABLE_H

#define UEFI_SLR_TABLE_GUID \
    { 0x877a9b2a, 0x0385, 0x45d1, { 0xa0, 0x34, 0x9d, 0xac, 0x9c, 0x9e, 0x56, 0x5f }}

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
    uint16_t tag;
    uint16_t size;
} __packed;

/*
 * Boot loader context
 */
struct slr_bl_context
{
    uint16_t bootloader;
    uint16_t reserved;
    uint64_t context;
} __packed;

/*
 * DRTM Dynamic Launch Configuration
 */
struct slr_entry_dl_info
{
    struct slr_entry_hdr hdr;
    struct slr_bl_context bl_context;
    uint64_t dl_handler;
    uint64_t dce_base;
    uint32_t dce_size;
    uint64_t dlme_entry;
} __packed;

/*
 * TPM Log Information
 */
struct slr_entry_log_info
{
    struct slr_entry_hdr hdr;
    uint16_t format;
    uint16_t reserved;
    uint64_t addr;
    uint32_t size;
} __packed;

/*
 * DRTM Measurement Policy
 */
struct slr_entry_policy
{
    struct slr_entry_hdr hdr;
    uint16_t revision;
    uint16_t nr_entries;
    /* policy_entries[] */
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
    uint64_t entity;
    uint64_t size;
    char evt_info[TPM_EVENT_INFO_LENGTH];
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
    uint64_t saved_misc_enable_msr;
    struct slr_txt_mtrr_state saved_bsp_mtrrs;
} __packed;

/*
 * AMD SKINIT Info table
 */
struct slr_entry_amd_info
{
    struct slr_entry_hdr hdr;
} __packed;

/*
 * ARM DRTM Info table
 */
struct slr_entry_arm_info
{
    struct slr_entry_hdr hdr;
} __packed;

struct slr_entry_uefi_config
{
    struct slr_entry_hdr hdr;
    uint16_t revision;
    uint16_t nr_entries;
    /* uefi_cfg_entries[] */
} __packed;

struct slr_uefi_cfg_entry
{
    uint16_t pcr;
    uint16_t reserved;
    uint64_t cfg; /* address or value */
    uint32_t size;
    char evt_info[TPM_EVENT_INFO_LENGTH];
} __packed;

static inline void *
slr_end_of_entries(struct slr_table *table)
{
    return (uint8_t *)table + table->size;
}

static inline struct slr_entry_hdr *
slr_next_entry(struct slr_table *table, struct slr_entry_hdr *curr)
{
    struct slr_entry_hdr *next = (struct slr_entry_hdr *)
                                 ((uint8_t *)curr + curr->size);

    if ( (void *)next >= slr_end_of_entries(table) )
        return NULL;
    if ( next->tag == SLR_ENTRY_END )
        return NULL;

    return next;
}

static inline struct slr_entry_hdr *
slr_next_entry_by_tag (struct slr_table *table,
                       struct slr_entry_hdr *entry,
                       uint16_t tag)
{
    if ( !entry ) /* Start from the beginning */
        entry = (struct slr_entry_hdr *)((uint8_t *)table + sizeof(*table));

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

/*
 * slr_add_entry() and slr_init_table() were omitted to not have issues with
 * memcpy() usage.
 */

#endif /* _SLR_TABLE_H */
