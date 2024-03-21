/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Slaunch functions related to TPM.
 *
 * This file is built twice:
 *  1. For early 32b mode without paging when it also provides
 *     slaunch_measure_mbi() to be called from assembly.
 *  2. For 64b code.
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#include <xen/compiler.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/multiboot2.h>
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

void asmlinkage slaunch_measure_mbi(const multiboot2_fixed_t *mbi,
                                    uint32_t slrt_pa)
{
    /* Need this to implement slaunch_get_slrt() for early TPM code. */
    slrt_location = slrt_pa;

    slaunch_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (const uint8_t *)mbi,
                        mbi->total_size, DLE_EVTYPE_SLAUNCH, NULL, 0);
}

#endif  /* __EARLY_SLAUNCH__ */

static struct tpm_log_hashes
create_log_event12(struct txt_ev_log_container_12 *evt_log,
                   uint32_t evt_log_size, uint32_t pcr, uint32_t type,
                   const uint8_t *data, unsigned data_size)
{
    struct tpm_log_hashes log_hashes = {0};

    struct TPM12_PCREvent *new_entry;

    if (evt_log == NULL)
        return log_hashes;

    if ( slaunch_is_amd_drtm() )
    {
        /*
         * On AMD, TXT-compatible structure is stored as vendor data of
         * TCG-defined event log header.
         */
        struct tpm1_spec_id_event *spec_id = (void *)evt_log;
        evt_log = (struct txt_ev_log_container_12 *)&spec_id->vendorInfo[0];
    }

    new_entry = (void *)evt_log + evt_log->NextEventOffset;

    /*
     * Check if there is enough space left for new entry.
     * Note: it is possible to introduce a gap in event log if entry with big
     * data_size is followed by another entry with smaller data. Maybe we should
     * cap the event log size in such case?
     */
    if ( evt_log->NextEventOffset + sizeof(struct TPM12_PCREvent) + data_size >
         evt_log_size )
        return log_hashes;

    evt_log->NextEventOffset += sizeof(struct TPM12_PCREvent) + data_size;

    new_entry->PCRIndex = pcr;
    new_entry->Type = type;
    new_entry->Size = data_size;

    if ( data != NULL && data_size > 0 )
        memcpy(new_entry->Data, data, data_size);

    log_hashes.count = 1;
    log_hashes.hashes[0].alg = TPM_ALG_SHA1;
    log_hashes.hashes[0].size = SHA1_DIGEST_SIZE;
    log_hashes.hashes[0].data = new_entry->Digest;

    return log_hashes;
}

static struct heap_event_log_pointer_element2_1 *
find_evt_log_ext_data(struct tpm2_spec_id_event *evt_log)
{
    struct txt_os_sinit_data *os_sinit;
    struct txt_ext_data_element *ext_data;

    if ( slaunch_is_amd_drtm() )
    {
        /*
         * Event log pointer is defined by TXT specification, but
         * secure-kernel-loader provides a compatible structure in vendor data
         * of the log.
         */
        uint8_t *data_size =
            (uint8_t *)&evt_log->digestSizes[evt_log->digestCount];
        if ( *data_size != sizeof(struct heap_event_log_pointer_element2_1) )
            return NULL;

        /* Vendor data directly follows a single-byte size. */
        return (struct heap_event_log_pointer_element2_1 *)(data_size + 1);
    }

    os_sinit = txt_start(__va(txt_read(TXTCR_HEAP_BASE)), TXT_OS2SINIT);
    ext_data = txt_find_ext_data_element(os_sinit,
                                         TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1);
    if ( ext_data == NULL )
        return NULL;

    return (struct heap_event_log_pointer_element2_1 *)ext_data->data;
}

static struct tpm_log_hashes
create_log_event20(struct tpm2_spec_id_event *evt_log, uint32_t evt_log_size,
                   uint32_t pcr, uint32_t type, const uint8_t *data,
                   unsigned data_size)
{
    struct tpm_log_hashes log_hashes = {0};

    struct heap_event_log_pointer_element2_1 *log_ext_data;
    struct tpm2_pcr_event_header *new_entry;
    uint32_t entry_size;
    unsigned i;
    uint8_t *p;

    if (evt_log == NULL)
        return log_hashes;

    log_ext_data = find_evt_log_ext_data(evt_log);
    if ( log_ext_data == NULL )
        return log_hashes;

    entry_size = sizeof(*new_entry);
    for ( i = 0; i < evt_log->digestCount; ++i )
    {
        entry_size += sizeof(uint16_t); /* hash type */
        entry_size += evt_log->digestSizes[i].digestSize;
    }
    entry_size += sizeof(uint32_t); /* data size field */
    entry_size += data_size;

    /*
     * Check if there is enough space left for new entry.
     * Note: it is possible to introduce a gap in event log if entry with big
     * data_size is followed by another entry with smaller data. Maybe we should
     * cap the event log size in such case?
     */
    if ( log_ext_data->next_record_offset + entry_size > evt_log_size )
        return log_hashes;

    new_entry = (void *)evt_log + log_ext_data->next_record_offset;
    log_ext_data->next_record_offset += entry_size;

    new_entry->pcrIndex = pcr;
    new_entry->eventType = type;
    new_entry->digestCount = evt_log->digestCount;

    p = &new_entry->digests[0];
    for ( i = 0; i < evt_log->digestCount; ++i )
    {
        uint16_t alg = evt_log->digestSizes[i].algId;
        uint16_t size = evt_log->digestSizes[i].digestSize;

        *(uint16_t *)p = alg;
        p += sizeof(uint16_t);

        log_hashes.hashes[i].alg = alg;
        log_hashes.hashes[i].size = size;
        log_hashes.hashes[i].data = p;
        p += size;

        /* This is called "OneDigest" in TXT Software Development Guide. */
        memset(log_hashes.hashes[i].data, 0, size);
        log_hashes.hashes[i].data[0] = 1;
    }
    log_hashes.count = evt_log->digestCount;

    *(uint32_t *)p = data_size;
    p += sizeof(uint32_t);

    if ( data != NULL && data_size > 0 )
        memcpy(p, data, data_size);

    return log_hashes;
}

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
        /*
         * Event log is used to verify measurements, but values of PCRs is the
         * real authoritative source of information, so keep going if there is
         * no log as secrets may still be correctly unsealed by TPM.
         */
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
    uint8_t discarded_digests[SHA2_256_DIGEST_SIZE];
    struct tpm_log_hashes log_hashes;
    uint32_t rc;

    slaunch_find_log(slaunch_get_slrt(), &evt_log_paddr, &evt_log_size);

    if ( tpm_is_tpm1() )
    {
        struct txt_ev_log_container_12 *evt_log = __va(evt_log_paddr);

        log_hashes = create_log_event12(evt_log, evt_log_size, pcr, type,
                                        log_data, log_data_size);
    }
    else
    {
        struct tpm2_spec_id_event *evt_log = __va(evt_log_paddr);

        log_hashes = create_log_event20(evt_log, evt_log_size, pcr, type,
                                        log_data, log_data_size);

        if ( log_hashes.count == 0 )
        {
            /*
             * Because TPM2 supports multiple PCR banks, the list of digests is
             * also used to indicate which banks to extend.  Thus avoid passing
             * an empty list of digests to have a chance of something being
             * extended even without event log.
             */
            log_hashes = (struct tpm_log_hashes) {
                .count = 2,
                .hashes = {
                    {
                        .alg = TPM_ALG_SHA1,
                        .size = SHA1_DIGEST_SIZE,
                        .data = discarded_digests,
                    },
                    {
                        .alg = TPM_ALG_SHA256,
                        .size = SHA2_256_DIGEST_SIZE,
                        .data = discarded_digests,
                    },
                },
            };
        }
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
