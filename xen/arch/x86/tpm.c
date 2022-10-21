/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o. All rights reserved.
 *
 * This file is built twice:
 *  1. For early 32b mode without paging the code sends data to be hashed to
 *     TPM.
 *  2. For 64b code which computes hashes and only extends them into PCRs.
 */

#include <xen/sha1.h>
#include <xen/string.h>
#include <xen/types.h>

#include <asm/tpm.h>
#include <asm/tpm1.h>

#ifdef __EARLY_TPM__

#include <xen/macros.h>

#ifdef __va
#error "__va defined in non-paged mode!"
#endif

#define __va(x)     _p(x)

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

#else   /* __EARLY_TPM__ */

#include <xen/mm.h>
#include <xen/pfn.h>

#endif  /* __EARLY_TPM__ */

#define TPM_LOC_REG(loc, reg)   (0x1000 * (loc) + (reg))

#define swap16(x)       __builtin_bswap16(x)
#define swap32(x)       __builtin_bswap32(x)

/******************************** MMIO helpers ********************************/

static uint32_t tpm_read32(unsigned int reg)
{
    return *(volatile uint32_t *)__va(TPM_MMIO_BASE + reg);
}

static uint16_t tpm_read16(unsigned int reg)
{
    return *(volatile uint16_t *)__va(TPM_MMIO_BASE + reg);
}

static uint8_t tpm_read8(unsigned int reg)
{
    return *(volatile uint8_t *)__va(TPM_MMIO_BASE + reg);
}

static void tpm_write8(unsigned int reg, uint8_t val)
{
    *(volatile uint8_t *)__va(TPM_MMIO_BASE + reg) = val;
}

/************************** TIS register definitions **************************/

#define TIS_ACCESS_(x)          TPM_LOC_REG(x, 0x00)
#define ACCESS_REQUEST_USE       (1 << 1)
#define ACCESS_ACTIVE_LOCALITY   (1 << 5)
#define TIS_INTF_CAPABILITY_(x) TPM_LOC_REG(x, 0x14)
#define INTF_VERSION_MASK        0x70000000
#define TIS_STS_(x)             TPM_LOC_REG(x, 0x18)
#define STS_FAMILY_MASK          0x0C000000
#define STS_EXPECT_DATA          (1 << 3)
#define STS_DATA_AVAIL           (1 << 4)
#define STS_TPM_GO               (1 << 5)
#define STS_COMMAND_READY        (1 << 6)
#define STS_VALID                (1 << 7)
#define TIS_BURST_COUNT_(x)     TPM_LOC_REG(x, 0x19)  /* the middle of STS */
#define TIS_DATA_FIFO_(x)       TPM_LOC_REG(x, 0x24)

/************************** TIS locality & command ****************************/

static void tis_request_locality(unsigned int loc)
{
    tpm_write8(TIS_ACCESS_(loc), ACCESS_REQUEST_USE);
    /* Check that locality was actually activated. */
    while ( !(tpm_read8(TIS_ACCESS_(loc)) & ACCESS_ACTIVE_LOCALITY) )
        ;
}

static void tis_relinquish_locality(unsigned int loc)
{
    tpm_write8(TIS_ACCESS_(loc), ACCESS_ACTIVE_LOCALITY);
}

static uint16_t tis_get_burst_count(unsigned int loc)
{
    return tpm_read16(TIS_BURST_COUNT_(loc));
}

static void tis_send_cmd(unsigned int loc, uint8_t *buf, unsigned int i_size,
                         unsigned int *o_size)
{
    /*
     * Values of "expect data" and "data available" bits count only when "valid"
     * field is set as well.
     */
    const unsigned int expect_data = STS_VALID | STS_EXPECT_DATA;
    const unsigned int data_avail = STS_VALID | STS_DATA_AVAIL;

    unsigned int i;
    unsigned int burst_count;

    /* Make sure TPM can accept a command. */
    if ( !(tpm_read8(TIS_STS_(loc)) & STS_COMMAND_READY) )
    {
        /* Abort current command. */
        tpm_write8(TIS_STS_(loc), STS_COMMAND_READY);
        /* Wait until TPM is ready for a new one. */
        while ( !(tpm_read8(TIS_STS_(loc)) & STS_COMMAND_READY) )
            ;
    }

    i = 0;
    while ( i < i_size )
    {
        do
            burst_count = tis_get_burst_count(loc);
        while ( burst_count == 0 );

        while ( burst_count-- > 0 && i < i_size )
            tpm_write8(TIS_DATA_FIFO_(loc), buf[i++]);

        if ( i < i_size )
        {
            while ( (tpm_read8(TIS_STS_(loc)) & expect_data) != expect_data )
                ;
        }
    }

    tpm_write8(TIS_STS_(loc), STS_TPM_GO);

    /* Wait for the first byte of response. */
    while ( (tpm_read8(TIS_STS_(loc)) & data_avail) != data_avail )
        ;

    i = 0;
    do {
        do
            burst_count = tis_get_burst_count(loc);
        while ( burst_count == 0 );

        while ( burst_count-- > 0 && i < *o_size)
            buf[i++] = tpm_read8(TIS_DATA_FIFO_(loc));

        while ( !(tpm_read8(TIS_STS_(loc)) & STS_VALID) )
            ;
    } while ( i < *o_size &&
              (tpm_read8(TIS_STS_(loc)) & data_avail) == data_avail );

    *o_size = i;

    tpm_write8(TIS_STS_(loc), STS_COMMAND_READY);
}

/************************** Interface dispatch ********************************/

static void request_locality(unsigned int loc)
{
    tis_request_locality(loc);
}

static void relinquish_locality(unsigned int loc)
{
    tis_relinquish_locality(loc);
}

static void send_cmd(unsigned int loc, uint8_t *buf, unsigned int i_size,
                     unsigned int *o_size)
{
    tis_send_cmd(loc, buf, i_size, o_size);
}

bool tpm_is_tpm1(void)
{
    uint32_t intf_version;

    /*
     * If one of these conditions is true:
     *  - INTF_CAPABILITY_x.interfaceVersion is 0 (TIS <= 1.21)
     *  - INTF_CAPABILITY_x.interfaceVersion is 2 (TIS == 1.3)
     *  - STS_x.tpmFamily is 0
     * we're dealing with TPM1.2.
     */
    intf_version = tpm_read32(TIS_INTF_CAPABILITY_(0)) & INTF_VERSION_MASK;
    return (intf_version == 0x00000000 || intf_version == 0x20000000 ||
            !(tpm_read32(TIS_STS_(0)) & STS_FAMILY_MASK));
}

/****************************** TPM1.2 specific *******************************/

#ifdef __EARLY_TPM__
/*
 * TPM1.2 is required to support commands of up to 1101 bytes, vendors rarely
 * go above that. Limit maximum size of block of data to be hashed to 1024.
 */
#define MAX_HASH_BLOCK      1024
#define CMD_RSP_BUF_SIZE    (sizeof(struct sha1_update_cmd) + MAX_HASH_BLOCK)

union cmd_rsp {
    struct tpm_cmd_hdr c;
    struct tpm_rsp_hdr r;
    struct sha1_start_cmd start_c;
    struct sha1_start_rsp start_r;
    struct sha1_update_cmd update_c;
    struct sha1_update_rsp update_r;
    struct sha1_complete_extend_cmd finish_c;
    struct sha1_complete_extend_rsp finish_r;
    uint8_t buf[CMD_RSP_BUF_SIZE];
};

static uint32_t tpm12_hash_extend(unsigned int loc, const uint8_t *buf,
                                  unsigned int size, unsigned int pcr,
                                  const struct tpm_log_hashes *log_hashes)
{
    union cmd_rsp cmd_rsp;
    unsigned int max_bytes = MAX_HASH_BLOCK;
    unsigned int o_size = sizeof(cmd_rsp);
    uint32_t rc;

    request_locality(loc);

    cmd_rsp.start_c = (struct sha1_start_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(cmd_rsp.start_c)),
        .h.ordinal = swap32(TPM_ORD_SHA1Start),
    };

    send_cmd(loc, cmd_rsp.buf, swap32(cmd_rsp.c.paramSize), &o_size);
    if ( o_size < sizeof(cmd_rsp.start_r) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    if ( max_bytes > swap32(cmd_rsp.start_r.maxNumBytes) )
        max_bytes = swap32(cmd_rsp.start_r.maxNumBytes);

    while ( size > 64 )
    {
        if ( size < max_bytes )
            max_bytes = ROUNDDOWN(size, 64);

        o_size = sizeof(cmd_rsp);

        cmd_rsp.update_c = (struct sha1_update_cmd) {
            .h.tag = swap16(TPM_TAG_RQU_COMMAND),
            .h.paramSize = swap32(sizeof(cmd_rsp.update_c) + max_bytes),
            .h.ordinal = swap32(TPM_ORD_SHA1Update),
            .numBytes = swap32(max_bytes),
        };
        memcpy(cmd_rsp.update_c.hashData, buf, max_bytes);

        send_cmd(loc, cmd_rsp.buf, swap32(cmd_rsp.c.paramSize), &o_size);
        if ( o_size < sizeof(cmd_rsp.update_r) )
        {
            rc = TPM_INTERNAL_ERROR;
            goto error;
        }
        rc = swap32(cmd_rsp.r.returnCode);
        if ( rc != 0 )
            goto error;

        size -= max_bytes;
        buf += max_bytes;
    }

    o_size = sizeof(cmd_rsp);

    cmd_rsp.finish_c = (struct sha1_complete_extend_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(cmd_rsp.finish_c) + size),
        .h.ordinal = swap32(TPM_ORD_SHA1CompleteExtend),
        .pcrNum = swap32(pcr),
        .hashDataSize = swap32(size),
    };
    memcpy(cmd_rsp.finish_c.hashData, buf, size);

    send_cmd(loc, cmd_rsp.buf, swap32(cmd_rsp.c.paramSize), &o_size);
    if ( o_size < sizeof(cmd_rsp.finish_r) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    if ( log_hashes->count != 0 )
    {
        memcpy(log_hashes->hashes[0].data, cmd_rsp.finish_r.hashValue,
               SHA1_DIGEST_SIZE);
    }

    rc = 0;

 error:
    relinquish_locality(loc);
    return rc;
}

#else

union cmd_rsp {
    struct tpm_cmd_hdr c;
    struct tpm_rsp_hdr r;
    struct extend_cmd extend_c;
    struct extend_rsp extend_r;
};

static uint32_t tpm12_hash_extend(unsigned int loc, const uint8_t *buf,
                                  unsigned int size, unsigned int pcr,
                                  const struct tpm_log_hashes *log_hashes)
{
    union cmd_rsp cmd_rsp;
    unsigned int o_size = sizeof(cmd_rsp);
    uint32_t rc;

    request_locality(loc);

    cmd_rsp.extend_c = (struct extend_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(cmd_rsp.extend_c)),
        .h.ordinal = swap32(TPM_ORD_Extend),
        .pcrNum = swap32(pcr),
    };

    sha1(cmd_rsp.extend_c.inDigest, buf, size);
    if ( log_hashes->count != 0 )
    {
        memcpy(log_hashes->hashes[0].data, cmd_rsp.extend_c.inDigest,
               SHA1_DIGEST_SIZE);
    }

    send_cmd(loc, (uint8_t *)&cmd_rsp, swap32(cmd_rsp.c.paramSize), &o_size);
    if ( o_size < sizeof(cmd_rsp.extend_r) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    relinquish_locality(loc);

    rc = 0;

 error:
    return rc;
}

#endif /* __EARLY_TPM__ */

/************************** end of TPM1.2 specific ****************************/

uint32_t tpm_hash_extend(unsigned int loc, unsigned int pcr, const uint8_t *buf,
                         unsigned int size,
                         const struct tpm_log_hashes *log_hashes)
{
    if ( tpm_is_tpm1() )
    {
        if (log_hashes->count != 0 &&
            !(log_hashes->count == 1 &&
              log_hashes->hashes[0].alg == TPM_ALG_SHA1 &&
              log_hashes->hashes[0].size == SHA1_DIGEST_SIZE))
        {
#ifndef __EARLY_TPM__
            printk(XENLOG_ERR "Bad TPM1 log hash for PCR-%u\n", pcr);
#endif
            return TPM_INTERNAL_ERROR;
        }

        return tpm12_hash_extend(loc, buf, size, pcr, log_hashes);
    }

    return TPM_INTERNAL_ERROR;
}
