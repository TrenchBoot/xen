/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * A TPM driver for both normal and early boot environments.
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#ifndef X86_TPM_H
#define X86_TPM_H

#include <xen/types.h>

#define TPM_INTERNAL_ERROR  0xffffffffU

#define TPM_MMIO_BASE  0xfed40000U
#define TPM_MMIO_SIZE  0x00010000U

/* These are defined for TPM2, but they are used by generic API. */
#define TPM_ALG_SHA1    0x0004
#define TPM_ALG_SHA256  0x000b
#define TPM_ALG_NULL    0x0010

/*
 * These two structures are for convenience, they don't correspond to anything
 * in any specification.
 */
struct tpm_log_hash {
    uint16_t alg;  /* TPM_ALG_* */
    uint16_t size;
    uint8_t *data; /* Non-owning reference to a buffer inside log entry. */
};
/* Should be more than enough for now and awhile in the future. */
#define MAX_TPM_HASH_COUNT 8
struct tpm_log_hashes {
    uint32_t count;
    struct tpm_log_hash hashes[MAX_TPM_HASH_COUNT];
};

/* All fields of the following structs are big endian. */

struct tpm_cmd_hdr {
    uint16_t tag;
    uint32_t paramSize;
    uint32_t ordinal;
} __packed;

struct tpm_rsp_hdr {
    uint16_t tag;
    uint32_t paramSize;
    uint32_t returnCode;
} __packed;

/* Checks whether TPM belongs to TPM 1 family, the only alternative is TPM 2. */
bool tpm_is_tpm1(void);

/*
 * The list of hashes must either be empty or contain nothing but SHA1 hash when
 * tpm_is_tpm1() returns true.
 *
 * When tpm_is_tpm1() returns false, the list of digests can also be used to
 * determine which hashes to extend.  The only hashes that are guaranteed to be
 * supported are SHA1 and SHA256, all other digests need to be pre-filled by
 * the caller with some placeholder value.
 *
 * Returns:
 *  - TPM error code when < 4096 (0 means success)
 *  - TPM_INTERNAL_ERROR on invalid invocation or a failure to communicate with
 *    a TPM device
 */
uint32_t tpm_hash_extend(unsigned int loc, unsigned int pcr, const uint8_t *buf,
                         unsigned int size,
                         const struct tpm_log_hashes *log_hashes);

#endif /* X86_TPM_H */
