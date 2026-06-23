/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Copyright (c) 2023, Apertus Solutions, LLC
 * All rights reserved.
 */

#ifndef __TPM_H__
#define __TPM_H__

struct secdev_handle *tpm_driver_init(void);

int tpm_extend_domain(
    const unsigned char *kern, size_t kern_size, const unsigned char *initrd,
    size_t initrd_size);
#endif
