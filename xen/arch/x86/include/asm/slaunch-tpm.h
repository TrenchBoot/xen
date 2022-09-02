/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TPM-related functions of Slaunch.  Can be used in both normal and early boot
 * environments.
 *
 * Copyright (c) 2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#ifndef X86_SLAUNCH_TPM_H
#define X86_SLAUNCH_TPM_H

#include <xen/types.h>

struct slr_table;

void slaunch_find_log(const struct slr_table *slrt, paddr_t *evt_log,
                      uint32_t *evt_log_size);

#endif /* X86_SLAUNCH_TPM_H */
