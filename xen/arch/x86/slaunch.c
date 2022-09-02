/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/compiler.h>
#include <xen/init.h>
#include <xen/macros.h>
#include <xen/mm.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/e820.h>
#include <asm/intel-txt.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/slaunch.h>

/*
 * These variables are assigned to by the code near Xen's entry point.
 *
 * slaunch_active is not __initdata to allow checking for an active Secure
 * Launch boot at any point.
 */
bool __ro_after_init slaunch_active;
uint32_t __initdata slaunch_slrt; /* physical address */

/*
 * Using slaunch_active in head.S assumes it's a single byte in size, so enforce
 * this assumption.
 */
static void __maybe_unused compile_time_checks(void)
{
    BUILD_BUG_ON(sizeof(slaunch_active) != 1);
}

struct slr_table *__init slaunch_get_slrt(void)
{
    static struct slr_table *__initdata slrt;

    if ( slrt == NULL )
    {
        int rc;

        slrt = __va(slaunch_slrt);

        rc = slaunch_map_l2(slaunch_slrt, PAGE_SIZE);
        BUG_ON(rc != 0);

        if ( slrt->magic != SLR_TABLE_MAGIC )
            panic("SLRT has invalid magic value: %#x!\n", slrt->magic);
        /* XXX: are newer revisions allowed? */
        if ( slrt->revision != SLR_TABLE_REVISION )
            panic("SLRT is of unsupported revision: %#x!\n", slrt->revision);
        if ( slrt->architecture != SLR_INTEL_TXT )
            panic("SLRT is for unexpected architecture: %#x!\n",
                  slrt->architecture);
        if ( slrt->size > slrt->max_size )
            panic("SLRT is larger than its max size: %#x > %#x!\n",
                  slrt->size, slrt->max_size);

        if ( slrt->size > PAGE_SIZE )
        {
            rc = slaunch_map_l2(slaunch_slrt, slrt->size);
            BUG_ON(rc != 0);
        }
    }

    return slrt;
}

void __init slaunch_map_mem_regions(void)
{
    paddr_t evt_log_addr;
    uint32_t evt_log_size;

    /* Vendor-specific part. */
    txt_map_mem_regions();

    find_evt_log(slaunch_get_slrt(), &evt_log_addr, &evt_log_size);
    if ( evt_log_addr != 0 )
    {
        int rc = slaunch_map_l2(evt_log_addr, evt_log_size);
        BUG_ON(rc != 0);
    }
}

void __init slaunch_reserve_mem_regions(void)
{
    paddr_t evt_log_addr;
    uint32_t evt_log_size;

    /* Vendor-specific part. */
    txt_reserve_mem_regions();

    find_evt_log(slaunch_get_slrt(), &evt_log_addr, &evt_log_size);
    if ( evt_log_addr != 0 )
    {
        int ok;

        printk("SLAUNCH: reserving event log [%#lx, %#lx)\n", evt_log_addr,
               evt_log_addr + evt_log_size);
        ok = reserve_e820_ram(&e820_raw, evt_log_addr,
                              evt_log_addr + evt_log_size);
        BUG_ON(!ok);
    }
}

int __init slaunch_map_l2(paddr_t paddr, size_t size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);

    pages = ROUNDUP(pages, 1ULL << L2_PAGETABLE_SHIFT) >> PAGE_SHIFT;

    BUG_ON(paddr >= (1ULL << 32));
    BUG_ON(paddr + pages * PAGE_SIZE >= (1ULL << 32));

    if ( aligned_paddr + pages * PAGE_SIZE <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT )
    {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return map_pages_to_xen((uintptr_t)__va(aligned_paddr),
                            maddr_to_mfn(aligned_paddr),
                            pages, PAGE_HYPERVISOR);
}
