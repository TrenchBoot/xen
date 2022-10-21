/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/sha1.h>
#include <xen/string.h>
#include <xen/types.h>

#include <asm/intel-txt.h>
#include <asm/slaunch.h>
#include <asm/tpm.h>
#include <asm/tpm1.h>

#ifdef __EARLY_SLAUNCH__

#ifdef __va
#error "__va defined in non-paged mode!"
#endif

#define __va(x)     _p(x)

/* Implementation of slaunch_get_slrt() for early TPM code. */
static uint32_t slrt_location;
struct slr_table *slaunch_get_slrt(void)
{
    return __va(slrt_location);
}

/*
 * The code is being compiled as a standalone binary without linking to any
 * other part of Xen.  Providing implementation of builtin functions in this
 * case is necessary if compiler chooses to not use an inline builtin.
 */
void *(memcpy)(void *dest, const void *src, size_t n)
{
    const uint8_t *s = src;
    uint8_t *d = dest;

    while ( n-- )
        *d++ = *s++;

    return dest;
}

#else   /* __EARLY_SLAUNCH__ */

#include <xen/mm.h>
#include <xen/pfn.h>

#endif  /* __EARLY_SLAUNCH__ */

#define TPM_LOC_REG(loc, reg)   (0x1000 * (loc) + (reg))

#define TPM_ACCESS_(x)          TPM_LOC_REG(x, 0x00)
#define ACCESS_REQUEST_USE       (1 << 1)
#define ACCESS_ACTIVE_LOCALITY   (1 << 5)
#define TPM_INTF_CAPABILITY_(x) TPM_LOC_REG(x, 0x14)
#define INTF_VERSION_MASK        0x70000000
#define TPM_STS_(x)             TPM_LOC_REG(x, 0x18)
#define TPM_FAMILY_MASK          0x0C000000
#define STS_EXPECT_DATA          (1 << 3)
#define STS_DATA_AVAIL           (1 << 4)
#define STS_TPM_GO               (1 << 5)
#define STS_COMMAND_READY        (1 << 6)
#define STS_VALID                (1 << 7)
#define TPM_BURST_COUNT_(x)     TPM_LOC_REG(x, 0x19)  /* the middle of STS */
#define TPM_DATA_FIFO_(x)       TPM_LOC_REG(x, 0x24)

#define swap16(x)       __builtin_bswap16(x)
#define swap32(x)       __builtin_bswap32(x)

static inline volatile uint32_t tis_read32(unsigned reg)
{
    return *(volatile uint32_t *)__va(TPM_TIS_BASE + reg);
}

static inline volatile uint16_t tis_read16(unsigned reg)
{
    return *(volatile uint16_t *)__va(TPM_TIS_BASE + reg);
}

static inline volatile uint8_t tis_read8(unsigned reg)
{
    return *(volatile uint8_t *)__va(TPM_TIS_BASE + reg);
}

static inline void tis_write8(unsigned reg, uint8_t val)
{
    *(volatile uint8_t *)__va(TPM_TIS_BASE + reg) = val;
}

static inline void request_locality(unsigned loc)
{
    tis_write8(TPM_ACCESS_(loc), ACCESS_REQUEST_USE);
    /* Check that locality was actually activated. */
    while ( (tis_read8(TPM_ACCESS_(loc)) & ACCESS_ACTIVE_LOCALITY) == 0 );
}

static inline void relinquish_locality(unsigned loc)
{
    tis_write8(TPM_ACCESS_(loc), ACCESS_ACTIVE_LOCALITY);
}

static inline uint16_t get_burst_count(unsigned loc)
{
    return tis_read16(TPM_BURST_COUNT_(loc));
}

static void send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                     unsigned *o_size)
{
    /*
     * Values of "expect data" and "data available" bits count only when "valid"
     * field is set as well.
     */
    const unsigned expect_data = STS_VALID | STS_EXPECT_DATA;
    const unsigned data_avail = STS_VALID | STS_DATA_AVAIL;

    unsigned i;
    unsigned burst_count;

    /* Make sure TPM can accept a command. */
    if ( (tis_read8(TPM_STS_(loc)) & STS_COMMAND_READY) == 0 )
    {
        /* Abort current command. */
        tis_write8(TPM_STS_(loc), STS_COMMAND_READY);
        /* Wait until TPM is ready for a new one. */
        while ( (tis_read8(TPM_STS_(loc)) & STS_COMMAND_READY) == 0 );
    }

    i = 0;
    while ( i < i_size )
    {
        do
            burst_count = get_burst_count(loc);
        while ( burst_count == 0 );

        while ( burst_count-- > 0 && i < i_size )
            tis_write8(TPM_DATA_FIFO_(loc), buf[i++]);

        if ( i < i_size )
            while ( (tis_read8(TPM_STS_(loc)) & expect_data) != expect_data );
    }

    tis_write8(TPM_STS_(loc), STS_TPM_GO);

    /* Wait for the first byte of response. */
    while ( (tis_read8(TPM_STS_(loc)) & data_avail) != data_avail );

    i = 0;
    do {
        do
            burst_count = get_burst_count(loc);
        while ( burst_count == 0 );

        while ( burst_count-- > 0 && i < *o_size)
            buf[i++] = tis_read8(TPM_DATA_FIFO_(loc));

        while ( (tis_read8(TPM_STS_(loc)) & STS_VALID) == 0 );
    } while ( i < *o_size &&
              (tis_read8(TPM_STS_(loc)) & data_avail) == data_avail );

    if ( i < *o_size )
        *o_size = i;

    tis_write8(TPM_STS_(loc), STS_COMMAND_READY);
}

static inline bool is_tpm12(void)
{
    /*
     * If one of these conditions is true:
     *  - INTF_CAPABILITY_x.interfaceVersion is 0 (TIS <= 1.21)
     *  - INTF_CAPABILITY_x.interfaceVersion is 2 (TIS == 1.3)
     *  - STS_x.tpmFamily is 0
     * we're dealing with TPM1.2.
     */
    uint32_t intf_version = tis_read32(TPM_INTF_CAPABILITY_(0))
                          & INTF_VERSION_MASK;
    return (intf_version == 0x00000000 || intf_version == 0x20000000 ||
            (tis_read32(TPM_STS_(0)) & TPM_FAMILY_MASK) == 0);
}

/****************************** TPM1.2 specific *******************************/

#ifdef __EARLY_SLAUNCH__
/*
 * TPM1.2 is required to support commands of up to 1101 bytes, vendors rarely
 * go above that. Limit maximum size of block of data to be hashed to 1024.
 */
#define MAX_HASH_BLOCK      1024
#define CMD_RSP_BUF_SIZE    (sizeof(struct sha1_update_cmd) + MAX_HASH_BLOCK)

union cmd_rsp {
    struct sha1_start_cmd start_c;
    struct sha1_start_rsp start_r;
    struct sha1_update_cmd update_c;
    struct sha1_update_rsp update_r;
    struct sha1_complete_extend_cmd finish_c;
    struct sha1_complete_extend_rsp finish_r;
    uint8_t buf[CMD_RSP_BUF_SIZE];
};

/* Returns true on success. */
static bool tpm12_hash_extend(unsigned loc, const uint8_t *buf, unsigned size,
                              unsigned pcr, uint8_t *out_digest)
{
    union cmd_rsp cmd_rsp;
    unsigned max_bytes = MAX_HASH_BLOCK;
    unsigned o_size = sizeof(cmd_rsp);
    bool success = false;

    request_locality(loc);

    cmd_rsp.start_c = (struct sha1_start_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct sha1_start_cmd)),
        .h.ordinal = swap32(TPM_ORD_SHA1Start),
    };

    send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_start_cmd), &o_size);
    if ( o_size < sizeof(struct sha1_start_rsp) )
        goto error;

    if ( max_bytes > swap32(cmd_rsp.start_r.maxNumBytes) )
        max_bytes = swap32(cmd_rsp.start_r.maxNumBytes);

    while ( size > 64 )
    {
        if ( size < max_bytes )
            max_bytes = size & ~(64 - 1);

        o_size = sizeof(cmd_rsp);

        cmd_rsp.update_c = (struct sha1_update_cmd){
            .h.tag = swap16(TPM_TAG_RQU_COMMAND),
            .h.paramSize = swap32(sizeof(struct sha1_update_cmd) + max_bytes),
            .h.ordinal = swap32(TPM_ORD_SHA1Update),
            .numBytes = swap32(max_bytes),
        };
        memcpy(cmd_rsp.update_c.hashData, buf, max_bytes);

        send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_update_cmd) + max_bytes,
                 &o_size);
        if ( o_size < sizeof(struct sha1_update_rsp) )
            goto error;

        size -= max_bytes;
        buf += max_bytes;
    }

    o_size = sizeof(cmd_rsp);

    cmd_rsp.finish_c = (struct sha1_complete_extend_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct sha1_complete_extend_cmd) + size),
        .h.ordinal = swap32(TPM_ORD_SHA1CompleteExtend),
        .pcrNum = swap32(pcr),
        .hashDataSize = swap32(size),
    };
    memcpy(cmd_rsp.finish_c.hashData, buf, size);

    send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_complete_extend_cmd) + size,
             &o_size);
    if ( o_size < sizeof(struct sha1_complete_extend_rsp) )
        goto error;

    if ( out_digest != NULL )
        memcpy(out_digest, cmd_rsp.finish_r.hashValue, SHA1_DIGEST_SIZE);

    success = true;

error:
    relinquish_locality(loc);
    return success;
}

#else

union cmd_rsp {
    struct extend_cmd extend_c;
    struct extend_rsp extend_r;
};

/* Returns true on success. */
static bool tpm12_hash_extend(unsigned loc, const uint8_t *buf, unsigned size,
                              unsigned pcr, uint8_t *out_digest)
{
    union cmd_rsp cmd_rsp;
    unsigned o_size = sizeof(cmd_rsp);

    sha1(out_digest, buf, size);

    request_locality(loc);

    cmd_rsp.extend_c = (struct extend_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct extend_cmd)),
        .h.ordinal = swap32(TPM_ORD_Extend),
        .pcrNum = swap32(pcr),
    };

    memcpy(cmd_rsp.extend_c.inDigest, out_digest, SHA1_DIGEST_SIZE);

    send_cmd(loc, (uint8_t *)&cmd_rsp, sizeof(struct extend_cmd), &o_size);

    relinquish_locality(loc);

    return (o_size >= sizeof(struct extend_rsp));
}

#endif /* __EARLY_SLAUNCH__ */

static void *create_log_event12(struct txt_ev_log_container_12 *evt_log,
                                uint32_t evt_log_size, uint32_t pcr,
                                uint32_t type, const uint8_t *data,
                                unsigned data_size)
{
    struct TPM12_PCREvent *new_entry;

    new_entry = (void *)(((uint8_t *)evt_log) + evt_log->NextEventOffset);

    /*
     * Check if there is enough space left for new entry.
     * Note: it is possible to introduce a gap in event log if entry with big
     * data_size is followed by another entry with smaller data. Maybe we should
     * cap the event log size in such case?
     */
    if ( evt_log->NextEventOffset + sizeof(struct TPM12_PCREvent) + data_size
         > evt_log_size )
        return NULL;

    evt_log->NextEventOffset += sizeof(struct TPM12_PCREvent) + data_size;

    new_entry->PCRIndex = pcr;
    new_entry->Type = type;
    new_entry->Size = data_size;

    if ( data && data_size > 0 )
        memcpy(new_entry->Data, data, data_size);

    return new_entry->Digest;
}

/************************** end of TPM1.2 specific ****************************/

void tpm_hash_extend(unsigned loc, unsigned pcr, const uint8_t *buf,
                     unsigned size, uint32_t type, const uint8_t *log_data,
                     unsigned log_data_size)
{
    paddr_t evt_log_paddr;
    uint32_t evt_log_size;

    find_evt_log(slaunch_get_slrt(), &evt_log_paddr, &evt_log_size);

    if ( is_tpm12() )
    {
        uint8_t sha1_digest[SHA1_DIGEST_SIZE];

        struct txt_ev_log_container_12 *evt_log = __va(evt_log_paddr);
        void *entry_digest = create_log_event12(evt_log, evt_log_size, pcr,
                                                type, log_data, log_data_size);

        /* Still need to write computed hash somewhere. */
        if ( entry_digest == NULL )
            entry_digest = sha1_digest;

        if ( !tpm12_hash_extend(loc, buf, size, pcr, entry_digest) )
        {
#ifndef __EARLY_SLAUNCH__
            printk(XENLOG_ERR "Extending PCR%u failed\n", pcr);
#endif
        }
    }
}

#ifdef __EARLY_SLAUNCH__
void asmlinkage tpm_extend_mbi(uint32_t *mbi, uint32_t slrt_pa)
{
    /* Need this to implement slaunch_get_slrt() for early TPM code. */
    slrt_location = slrt_pa;

    /* MBI starts with uint32_t total_size. */
    tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)mbi, *mbi,
                    DLE_EVTYPE_SLAUNCH, NULL, 0);
}
#endif
