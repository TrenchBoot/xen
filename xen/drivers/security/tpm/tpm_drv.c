/*
 * Copyright (c) 2023, Apertus Solutions, LLC
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


#include <xen/errno.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/types.h>

#include "../secdev.h"
#include "tpm.h"

#define TPM_MAX_HASH_ALG   4
#define TPM_PARAM_SHA1_MASK    1<<0
#define TPM_PARAM_SHA256_MASK  1<<1
#define TPM_PARAM_SHA384_MASK  1<<2
#define TPM_PARAM_SHA512_MASK  1<<3
#define TPM_PARAM_MAX_ALGO_MASK  (TPM_PARAM_SHA1_MASK|TPM_PARAM_SHA256_MASK| \
                                  TPM_PARAM_SHA384_MASK|TPM_PARAM_SHA512_MASK)
static int16_t param_algo_mask = -1;
static int16_t param_dom_locality = -1;
static int16_t param_dom_pcr = -1;
/*
 * [ algo-mask=<int>, dom-locality=<int>, dom-pcr=<int> ]
 */
static int __init cf_check parse_tpm_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !strncmp(s, "algo-mask", 9) )
            param_algo_mask = simple_strtoul(s+9, &s, 0);
        else if ( !strncmp(s, "dom-locality", 12) )
        {
            param_dom_locality = simple_strtoul(s+12, &s, 0);
            if ( param_dom_locality >= TPM_NR_LOCALITIES )
            {
                printk(XENLOG_WARNING"Invalid Locality from commandline.\n");
                param_dom_locality = -1;
            }
        }
        else if ( !strncmp(s, "dom-pcr", 7) )
        {
            param_dom_pcr = simple_strtoul(s+7, &s, 0);
            if ( param_dom_pcr >= TPM_NR_PCRS )
            {
                printk(XENLOG_WARNING"Invalid PCR from commandline.\n");
                param_dom_pcr = -1;
            }
        }
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("tpm", parse_tpm_param);

/* NOTE: will return the largest hash measured in *res */
int cf_check tpm_extend_buffer(secdev_opt_t *opts, secdev_result_t *res)
{
    struct tpm_if *t = get_tpm();
    hash_list_t hashes = { 0 };
    uint32_t pcr = param_dom_pcr < 0 ? opts->tpm.buffer.pcr : param_dom_pcr;
    uint32_t locality = param_dom_locality < 0 ? opts->tpm.buffer.locality :
                                                 param_dom_locality;
    int i;

    if ( t == NULL || t->cmds == NULL || t->cmds->pcr_extend != NULL )
        return -EFAULT;

    if ( pcr >= TPM_NR_PCRS || locality >= TPM_NR_LOCALITIES )
    {
        printk(XENLOG_ERR"%s: invalid PCR (%d) or Locality (%d) requested.\n",
            __func__, pcr, locality);
        return -EFAULT;
    }

    if ( opts->tpm.buffer.addr == NULL )
        return -EINVAL;

    for ( i = 0; i < TPM_MAX_HASH_ALG; i++ )
    {
        uint16_t algo_mask = 1<<i;
        hash_entry_t *entry = &hashes.entries[i];

        if ( !(param_algo_mask & algo_mask) )
            continue;

        switch ( algo_mask )
        {
        case TPM_PARAM_SHA1_MASK:
            entry->alg = HASH_ALG_SHA1;

            if ( !hash_buffer(opts->tpm.buffer.addr, opts->tpm.buffer.size,
                    &entry->hash, entry->alg) )
                return -EFAULT;

            res->tpm.measure.digest = entry->hash;

            /* TPM 1.2 only supports SHA1, break from loop */
            if ( t->version.major < TPM20_VER_MAJOR )
                goto buffer_tpm12_exit;

            break;
        case TPM_PARAM_SHA256_MASK:
            entry->alg = HASH_ALG_SHA256;

            if ( !hash_buffer(opts->tpm.buffer.addr, opts->tpm.buffer.size,
                    &entry->hash, entry->alg) )
                return -EFAULT;

            res->tpm.measure.digest = entry->hash;

            break;
        case TPM_PARAM_SHA384_MASK:
            entry->alg = HASH_ALG_SHA384;

            if ( !hash_buffer(opts->tpm.buffer.addr, opts->tpm.buffer.size,
                    &entry->hash, entry->alg) )
                return -EFAULT;

            res->tpm.measure.digest = entry->hash;

            break;
        case TPM_PARAM_SHA512_MASK:
            entry->alg = HASH_ALG_SHA512;

            if ( !hash_buffer(opts->tpm.buffer.addr, opts->tpm.buffer.size,
                    &entry->hash, entry->alg) )
                return -EFAULT;

            res->tpm.measure.digest = entry->hash;

            break;
        default:
            return -EFAULT;
        }

        hashes.count++;
    }

buffer_tpm12_exit:
    if ( !t->cmds->pcr_extend(t, locality, pcr, &hashes) )
        return -EFAULT;

    return 0;
}

static int hash_domain(
    hash_entry_t *entry, const unsigned char *kern, size_t kern_size,
    const unsigned char *initrd, size_t initrd_size, char *cmdline)
{

    if ( !hash_buffer(kern, kern_size, &entry->hash, entry->alg) )
        return -EFAULT;

    if ( initrd != NULL )
    {
        hash_t ih;

        if ( !hash_buffer(initrd, initrd_size, &ih, entry->alg) ||
             !extend_hash(&entry->hash, &ih, entry->alg) )
            return -EFAULT;
    }

    if ( cmdline != NULL )
    {
        size_t cmdlen = strlen(cmdline);
        hash_t ih;

        if ( !hash_buffer((unsigned char *)cmdline, cmdlen, &ih, entry->alg) ||
             !extend_hash(&entry->hash, &ih, entry->alg) )
            return -EFAULT;
    }

    return 0;
}

/* NOTE: will return the largest hash measured in *res */
int cf_check tpm_extend_domain(secdev_opt_t *opts, secdev_result_t *res)
{
    struct tpm_if *t = get_tpm();
    hash_list_t hashes = { 0 };
    uint32_t pcr = param_dom_pcr < 0 ? opts->tpm.domain.pcr : param_dom_pcr;
    uint32_t locality = param_dom_locality < 0 ? opts->tpm.domain.locality :
                                                 param_dom_locality;
    int i;

    if ( t == NULL || t->cmds == NULL || t->cmds->pcr_extend != NULL )
        return -EFAULT;

    if ( pcr >= TPM_NR_PCRS || locality >= TPM_NR_LOCALITIES )
    {
        printk(XENLOG_ERR"%s: invalid PCR (%d) or Locality (%d) requested.\n",
            __func__, pcr, locality);
        return -EFAULT;
    }

    if ( opts->tpm.domain.kern == NULL )
        return -EINVAL;

    for ( i = 0; i < TPM_MAX_HASH_ALG; i++ )
    {
        uint16_t algo_mask = 1<<i;
        hash_entry_t *entry = &hashes.entries[i];
        int ret;

        if ( !(param_algo_mask & algo_mask) )
            continue;

        switch ( algo_mask )
        {
        case TPM_PARAM_SHA1_MASK:

            entry->alg = HASH_ALG_SHA1;

            ret = hash_domain(entry, opts->tpm.domain.kern,
                    opts->tpm.domain.kern_size, opts->tpm.domain.initrd,
                    opts->tpm.domain.initrd_size, opts->tpm.domain.cmdline);
            if ( ret < 0 )
                return ret;

            res->tpm.measure.digest = entry->hash;

            /* TPM 1.2 only supports SHA1, break from loop */
            if ( t->version.major < TPM20_VER_MAJOR )
                goto domain_tpm12_exit;

            break;
        case TPM_PARAM_SHA256_MASK:
            entry->alg = HASH_ALG_SHA256;

            ret = hash_domain(entry, opts->tpm.domain.kern,
                    opts->tpm.domain.kern_size, opts->tpm.domain.initrd,
                    opts->tpm.domain.kern_size, opts->tpm.domain.cmdline);
            if ( ret < 0 )
                return ret;

            res->tpm.measure.digest = entry->hash;

            break;
        case TPM_PARAM_SHA384_MASK:
            entry->alg = HASH_ALG_SHA384;

            ret = hash_domain(entry, opts->tpm.domain.kern,
                    opts->tpm.domain.kern_size, opts->tpm.domain.initrd,
                    opts->tpm.domain.kern_size, opts->tpm.domain.cmdline);
            if ( ret < 0 )
                return ret;

            res->tpm.measure.digest = entry->hash;

            break;
        case TPM_PARAM_SHA512_MASK:
            entry->alg = HASH_ALG_SHA512;

            ret = hash_domain(entry, opts->tpm.domain.kern,
                    opts->tpm.domain.kern_size, opts->tpm.domain.initrd,
                    opts->tpm.domain.kern_size, opts->tpm.domain.cmdline);
            if ( ret < 0 )
                return ret;

            res->tpm.measure.digest = entry->hash;

            break;
        default:
            return -EFAULT;
        }

        hashes.count++;
    }

domain_tpm12_exit:
    if ( !t->cmds->pcr_extend(t, locality, pcr, &hashes) )
        return -EFAULT;

    return 0;
}

static struct secdev_handle  tpm_drv_handle = {
    .getrandom = NULL,
    .register_domain = NULL,
    .measure_buffer = tpm_extend_buffer,
    .measure_domain = tpm_extend_domain,
    .launch_domain = NULL,
    .direct_op = NULL,
};

struct secdev_handle *tpm_driver_init(void)
{
    struct tpm_if *t = get_tpm();

    if ( !tpm_detect() )
        return NULL;

    if ( (t->version.version == TPM_VER_12) &&
         !(param_algo_mask || TPM_PARAM_SHA1_MASK) )
    {
        printk(XENLOG_WARNING"Detected TPM1.2 but SHA1 not in requested algorithms.\n");
        param_algo_mask = TPM_PARAM_SHA1_MASK;
    }

    /* mask out any undefined bits */
    param_algo_mask &= TPM_PARAM_MAX_ALGO_MASK;

    return &tpm_drv_handle;
}
