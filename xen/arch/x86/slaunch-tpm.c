/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Slaunch functions related to TPM.
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#include <xen/macros.h>
#include <xen/slr-table.h>
#include <xen/types.h>

void slaunch_find_log(const struct slr_table *slrt, paddr_t *evt_log,
                      uint32_t *evt_log_size)
{
    const struct slr_entry_hdr *hdr;

    hdr = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_LOG_INFO);
    if ( hdr != NULL )
    {
        const struct slr_entry_log_info *log_info;
        log_info = container_of(hdr, const struct slr_entry_log_info, hdr);

        *evt_log = (uintptr_t)_p(log_info->addr);
        *evt_log_size = log_info->size;
    }
    else
    {
        /*
         * Event log is used to verify measurements, but values of PCRs is the
         * real authoritative source of information, so keep going if there is
         * no log as secrets may still be correctly unsealed by TPM.
         */
        *evt_log = 0;
        *evt_log_size = 0;
    }
}
