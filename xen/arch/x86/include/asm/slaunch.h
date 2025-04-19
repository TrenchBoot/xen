/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#ifndef X86_SLAUNCH_H
#define X86_SLAUNCH_H

#include <xen/types.h>

struct slaunch_early_init_results
{
    uint32_t mbi_pa;
    uint32_t slrt_pa;
} __packed;

/* Indicates an active Secure Launch boot. */
extern bool slaunch_active;

/* Holds physical address of SLRT. */
extern uint32_t slaunch_slrt;

#endif /* X86_SLAUNCH_H */
