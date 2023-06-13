/*
 * tpm.c: TPM-related support functions
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <asm/io.h>
#include <asm/processor.h>
#include <xen/lib.h>
#include <xen/lib/hash.h>
#include <xen/lib/sha1.h>
#include <xen/lib/sha2.h>
#include <asm/byteorder.h>

#include "tpm.h"

static struct tpm_if __tpm = {
    .version = {
        .version = TPM_VER_UNKNOWN,
    },
    .cur_loc = 0,
    .timeout.timeout_a = TIMEOUT_A,
    .timeout.timeout_b = TIMEOUT_B,
    .timeout.timeout_c = TIMEOUT_C,
    .timeout.timeout_d = TIMEOUT_D,
};

uint16_t tpm_alg_list[] = {HASH_ALG_SHA1, HASH_ALG_SHA256, HASH_ALG_SHA384, HASH_ALG_SHA512};
const uint8_t tpm_alg_list_count = ARRAY_SIZE(tpm_alg_list);

bool tpm_detect(void)
{
#ifdef __LITTLE_ENDIAN
    struct tpm_if *tpm = get_tpm(); /* Don't leave tpm as NULL */

    /* default to SHA1 */
    tpm->cur_alg = TPM_ALG_SHA1;

    /* Determine MMIO interface type and initial famly guess */
    mmio_detect_interface(tpm);

    if ( tpm->family == TPM_IF_20_CRB)
    {
        printk(XENLOG_INFO"TPM: appears to be a CRB TPM Family 0x%d\n",
            tpm->family);
        if ( tpm->hw->validate_locality(0) )
            printk(XENLOG_INFO"TPM: CRB_INF Locality 0 is open\n");
        else
        {
            printk(XENLOG_INFO"TPM: CRB_INF request access to Locality 0...\n");
            if ( !tpm->hw->request_locality(0) )
            {
                printk(XENLOG_ERR"TPM: CRB_INF Locality 0 request failed...\n");
                tpm->cmds = NULL;
                return false;
            }
        }
    }
    else
    {
        if ( tpm->hw->validate_locality(0) )
            printk(XENLOG_INFO"TPM: FIFO_INF Locality 0 is open\n");
        else
        {
            printk(XENLOG_ERR"TPM: FIFO_INF Locality 0 cannot be requested\n");
            tpm->cmds = NULL;
            return false;
        }
        /* determine TPM family from command check */
        if ( tpm_12_cmds.check() )
        {
            tpm->family = TPM_IF_12;
            printk(XENLOG_INFO"TPM: discrete TPM1.2 Family 0x%d\n", tpm->family);
        }
        else
        {
            tpm->family = TPM_IF_20_FIFO;
            printk(XENLOG_INFO"TPM: discrete TPM2.0 Family 0x%d\n", tpm->family);
        }
    }

    if (tpm->family == TPM_IF_12)
    {
        tpm->version.version = TPM_VER_12;
        tpm->cmds = &tpm_12_cmds;
    }
    else if ( tpm->family == TPM_IF_20_FIFO || tpm->family == TPM_IF_20_CRB )
    {
		tpm->version.version = TPM_VER_20;
        tpm->cmds = &tpm_20_cmds;
    }
    else
    {
		tpm->version.version = TPM_VER_UNKNOWN;
        tpm->cmds = NULL;

        return false;
    }

    return tpm->cmds->init(tpm);
#else
    printk(XENLOG_INFO"TPM: big endian platforms not supported\n");
    return false;
#endif
}

void tpm_print(struct tpm_if *ti)
{
    if ( ti == NULL )
        return;

    printk(XENLOG_INFO"TPM attribute:\n");
    printk(XENLOG_INFO"\t extend policy: %d\n", ti->extpol);
    printk(XENLOG_INFO"\t current alg id: 0x%x\n", ti->cur_alg);
    printk(XENLOG_INFO"\t timeout values: A: %u, B: %u, C: %u, D: %u\n",
        ti->timeout.timeout_a, ti->timeout.timeout_b,
        ti->timeout.timeout_c, ti->timeout.timeout_d);
}

struct tpm_if *get_tpm(void)
{
    return &__tpm;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
