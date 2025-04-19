/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/kernel.h>
#include <xen/slr-table.h>
#include <xen/types.h>

#include <asm/intel-txt.h>
#include <asm/slaunch.h>

void asmlinkage slaunch_early_init(uint32_t load_base_addr,
                                   uint32_t tgt_base_addr,
                                   uint32_t tgt_end_addr,
                                   struct slaunch_early_init_results *result)
{
    void *txt_heap;
    const struct txt_os_mle_data *os_mle;
    const struct slr_table *slrt;
    const struct slr_entry_hdr *entry;
    const struct slr_entry_intel_info *intel_info;

    txt_heap = txt_init();
    os_mle = txt_start(txt_heap, TXT_OS2MLE);

    if ( os_mle->slrt & ~0xffffffffULL )
        txt_reset(SLAUNCH_ERROR_BAD_SLRT_ADDRESS);

    result->slrt_pa = os_mle->slrt;

    slrt = (const struct slr_table *)result->slrt_pa;

    entry = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
    if ( entry == NULL )
        txt_reset(SLAUNCH_ERROR_NO_VENDOR_INFO);

    intel_info = container_of(entry, const struct slr_entry_intel_info, hdr);
    if ( intel_info->hdr.size != sizeof(*intel_info) )
        txt_reset(SLAUNCH_ERROR_BAD_VENDOR_INFO);

    result->mbi_pa = intel_info->boot_params_base;
}
