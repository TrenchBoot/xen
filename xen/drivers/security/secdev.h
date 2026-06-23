/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Copyright (c) 2023, Apertus Solutions, LLC
 * All rights reserved.
 */

#ifndef __SECDEV_H__
#define __SECDEV_H__

#include <xen/lib/hash.h>
#include <xen/secdev.h>

struct tpm_dev_result {
    union {
        struct {
            ssize_t len;
        } random;
        struct {
            hash_t digest;
        } measure;
    };
};

typedef union secdev_result {
    struct tpm_dev_result tpm;
} secdev_result_t;

struct secdev_handle {
    int (*getrandom)(secdev_opt_t *opts, secdev_result_t *res);
    int (*measure_buffer)(secdev_opt_t *opts, secdev_result_t *res);
    int (*register_domain)(secdev_opt_t *opts, secdev_result_t *res);
    int (*measure_domain)(secdev_opt_t *opts, secdev_result_t *res);
    int (*launch_domain)(secdev_opt_t *opts, secdev_result_t *res);
    int (*direct_op)(secdev_opt_t *opts, secdev_result_t *res);
};

#endif
