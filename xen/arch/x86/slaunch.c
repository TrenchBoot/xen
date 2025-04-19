/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/compiler.h>
#include <xen/init.h>
#include <xen/inttypes.h>
#include <xen/macros.h>
#include <xen/sections.h>

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
