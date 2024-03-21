/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Declarations related to Slaunch (an implementation of a DRTM launch).  This
 * header is consumed by both normal and early boot code and has to take the
 * two environments into account.
 *
 * More details about Slaunch are available at:
 *   https://trenchboot.org/specifications/Secure_Launch/
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#ifndef X86_SLAUNCH_H
#define X86_SLAUNCH_H

#include <xen/kernel.h>
#include <xen/slr-table.h>
#include <xen/types.h>

#include <asm/x86-vendors.h>

#define DRTM_LOC                   2
#define DRTM_CODE_PCR              17
#define DRTM_DATA_PCR              18

/*
 * Secure Launch event log entry types. The TXT specification defines the base
 * event value as 0x400 for DRTM values, use it regardless of the DRTM for
 * consistency.
 */
#define DLE_EVTYPE_BASE            0x400
#define DLE_EVTYPE_SLAUNCH         (DLE_EVTYPE_BASE + 0x102)
#define DLE_EVTYPE_SLAUNCH_START   (DLE_EVTYPE_BASE + 0x103)
#define DLE_EVTYPE_SLAUNCH_END     (DLE_EVTYPE_BASE + 0x104)

struct boot_info;

struct slaunch_early_init_results
{
    uint32_t mbi_pa;
    uint32_t slrt_pa;
} __packed;

#ifdef CONFIG_SLAUNCH
/* Indicates an active Secure Launch boot. */
extern bool slaunch_active;
#else
/*
 * This avoids `#ifdef CONFIG_SLAUNCH` around `if ( slaunch_active )` thanks to
 * dead code elimination.
 */
static bool slaunch_active = false;
#endif

/*
 * Holds physical address of SLRT.  Use slaunch_get_slrt() to access SLRT
 * instead of mapping where this points to.
 */
extern uint32_t slaunch_slrt;

#ifdef __EARLY_SLAUNCH__

static inline bool slaunch_is_amd_drtm(void)
{
    /*
     * asm/processor.h can't be included in early code, which means neither
     * cpuid() function nor boot_cpu_data can be used here.
     */
    uint32_t eax, ebx, ecx, edx;
    asm volatile ( "cpuid"
          : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
          : "0" (0), "c" (0) );
    return ebx == X86_VENDOR_AMD_EBX
        && ecx == X86_VENDOR_AMD_ECX
        && edx == X86_VENDOR_AMD_EDX;
}

#else   /* __EARLY_SLAUNCH__ */

#include <asm/cpufeature.h>

static inline bool slaunch_is_amd_drtm(void)
{
    return boot_cpu_data.x86_vendor == X86_VENDOR_AMD;
}

#endif  /* __EARLY_SLAUNCH__ */

/*
 * Retrieves pointer to SLRT.  Checks table's validity and maps it as necessary.
 */
struct slr_table *slaunch_get_slrt(void);

/*
 * Prepares for accesses to essential data structures setup by boot environment.
 */
void slaunch_map_mem_regions(void);

/* Marks regions of memory as used to avoid their corruption. */
void slaunch_reserve_mem_regions(void);

/* Measures essential parts of SLR table before making use of them. */
void slaunch_measure_slrt(void);

/*
 * Takes measurements of DRTM policy entries except for MBI and SLRT which
 * should have been measured by the time this is called. Also performs sanity
 * checks of the policy and panics on failure. In particular, the function
 * verifies that DRTM is consistent with modules obtained from MultibootInfo
 * (MBI) and written to struct boot_info in setup.c.
 */
void slaunch_process_drtm_policy(const struct boot_info *bi);

/*
 * This helper function is used to map memory below 4 GiB using L2 page tables
 * by aligning mapped regions to 2MB. This way page allocator (which at this
 * point isn't yet initialized) isn't needed for creating new L1 mappings. The
 * function also checks and skips memory already mapped by the prebuilt tables.
 *
 * There is no unmap_l2() because the function is meant to be used by the code
 * that accesses DRTM-related memory soon after which Xen rebuilds memory maps,
 * effectively dropping all existing mappings.
 *
 * Returns zero on success.
 */
int slaunch_map_l2(paddr_t paddr, size_t size);

#endif /* X86_SLAUNCH_H */
