/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Copyright (c) 2023, Apertus Solutions, LLC
 * All rights reserved.
 */

#ifndef __XEN_SECDEV_H__
#define __XEN_SECDEV_H__

#include <xen/types.h>

typedef enum secdev_id {
    SECDEV_TPM,
    SECDEV_ASP, /* Reserving for AMD PSP/ASP  */
    SECDEV_PLTN, /* Reserving for MS Pluton  */
} secdev_id_t;

#define SECDEV_SHA1_MASK    1<<0
#define SECDEV_SHA256_MASK  1<<1
#define SECDEV_SHA384_MASK  1<<2
#define SECDEV_SHA512_MASK  1<<3
#define SECDEV_MAX_ALGO_MASK  (SECDEV_SHA1_MASK|SECDEV_SHA256_MASK| \
                              SECDEV_SHA384_MASK|SECDEV_SHA512_MASK)

#define SECDEV_TPM_DEFAULT_LOCALITY 0
#define SECDEV_TPM_DEFAULT_PCR 15
struct tpm_dev_opt {
    union {
        struct {
            void *buf;
            size_t buf_size;
            uint32_t flags;
        } random;
        struct {
            uint8_t locality;
            uint8_t pcr;
            uint16_t algo_mask;
            unsigned char *addr;
            size_t size;
        } buffer;
        struct {
            uint8_t locality;
            uint8_t pcr;
            uint16_t algo_mask;
            unsigned char *kern;
            size_t kern_size;
            unsigned char *initrd;
            size_t initrd_size;
            char *cmdline;
        } domain;
    };
};

typedef union secdev_opt {
    struct tpm_dev_opt tpm;
} secdev_opt_t;

int secdev_init(void);
bool secdev_available(secdev_id_t dev_id);
ssize_t secdev_getrandom(secdev_id_t dev_id, secdev_opt_t *opts);
int secdev_measure_buffer(secdev_id_t dev_id, secdev_opt_t *opts);
int secdev_measure_domain(secdev_id_t dev_id, secdev_opt_t *opts);

#endif
