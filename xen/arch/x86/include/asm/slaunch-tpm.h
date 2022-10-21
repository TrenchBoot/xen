/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2026 3mdeb Sp. z o.o. All rights reserved.
 */

#ifndef X86_SLAUNCH_TPM_H
#define X86_SLAUNCH_TPM_H

#include <xen/types.h>

struct slr_table;

void slaunch_find_log(const struct slr_table *slrt, paddr_t *evt_log,
                      uint32_t *evt_log_size);

/*
 * Log data is optional (pass in NULL and/or zero size to indicate its absence).
 */
void slaunch_hash_extend(unsigned int loc, unsigned int pcr, const uint8_t *buf,
                         unsigned int size, uint32_t type,
                         const uint8_t *log_data, unsigned int log_data_size);

#endif /* X86_SLAUNCH_TPM_H */
