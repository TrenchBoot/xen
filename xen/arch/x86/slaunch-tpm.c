/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o. All rights reserved.
 *
 * This file is built twice:
 *  1. For early 32b mode without paging when it also provides tpm_extend_mbi()
 *     to be called from assembly.
 *  2. For 64b code.
 */

#include <xen/compiler.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/sha1.h>
#include <xen/sha2.h>
#include <xen/slr-table.h>
#include <xen/types.h>

#include <asm/intel-txt.h>
#include <asm/slaunch.h>
#include <asm/slaunch-tpm.h>
#include <asm/tpm.h>
#include <asm/tpm2.h>

#ifdef __EARLY_SLAUNCH__

#ifdef __va
#error "__va defined in non-paged mode!"
#endif

#define __va(x)  _p(x)

static uint32_t slrt_location;

/*
 * The code is being compiled as a standalone binary without linking to any
 * other part of Xen.  Providing implementation of builtin functions in this
 * case is necessary if compiler chooses to not use an inline builtin.
 */
void *(memset)(void *s, int c, size_t n)
{
    uint8_t *d = s;

    while ( n-- )
        *d++ = c;

    return s;
}

struct slr_table *slaunch_get_slrt(void)
{
    return _p(slrt_location);
}

void asmlinkage tpm_extend_mbi(const uint32_t *mbi, uint32_t slrt_pa)
{
    /* Need this to implement slaunch_get_slrt() for early TPM code. */
    slrt_location = slrt_pa;

    /* MBI starts with uint32_t total_size. */
    slaunch_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (const uint8_t *)mbi, *mbi,
                        DLE_EVTYPE_SLAUNCH, NULL, 0);
}

#endif  /* __EARLY_SLAUNCH__ */

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
        *evt_log = 0;
        *evt_log_size = 0;
    }
}

void slaunch_hash_extend(unsigned int loc, unsigned int pcr, const uint8_t *buf,
                         unsigned int size, uint32_t type,
                         const uint8_t *log_data, unsigned int log_data_size)
{
    paddr_t evt_log_paddr;
    uint32_t evt_log_size;
    struct tpm_log_hashes log_hashes;
    uint8_t sha1_digest[SHA1_DIGEST_SIZE];
    uint8_t sha256_digest[SHA2_256_DIGEST_SIZE];
    uint32_t rc;

    slaunch_find_log(slaunch_get_slrt(), &evt_log_paddr, &evt_log_size);

    if ( tpm_is_tpm1() )
    {
        log_hashes = (struct tpm_log_hashes){
            .count = 1,
            .hashes = {
                {
                    .alg = TPM_ALG_SHA1,
                    .size = SHA1_DIGEST_SIZE,
                    .data = sha1_digest,
                },
            },
        };
    }
    else
    {
        log_hashes = (struct tpm_log_hashes){
            .count = 2,
            .hashes = {
                {
                    .alg = TPM_ALG_SHA1,
                    .size = SHA1_DIGEST_SIZE,
                    .data = sha1_digest,
                },
                {
                    .alg = TPM_ALG_SHA256,
                    .size = SHA2_256_DIGEST_SIZE,
                    .data = sha256_digest,
                },
            },
        };
    }

    rc = tpm_hash_extend(loc, pcr, buf, size, &log_hashes);
    if (rc != 0)
    {
#ifndef __EARLY_SLAUNCH__
        printk(XENLOG_ERR "Extending PCR-%u failed with an error: 0x%08x\n",
               pcr, rc);
#endif
    }
}
