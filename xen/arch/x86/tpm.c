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
#include <xen/sha2.h>
#include <xen/string.h>
#include <xen/types.h>

#include <asm/tpm.h>
#include <asm/tpm1.h>
#include <asm/tpm2.h>

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

static void tpm_write32(unsigned int reg, uint32_t val)
{
    *(volatile uint32_t *)__va(TPM_MMIO_BASE + reg) = val;
}

static void tpm_write8(unsigned int reg, uint8_t val)
{
    *(volatile uint8_t *)__va(TPM_MMIO_BASE + reg) = val;
}

/************************** Interface detection *******************************/

#define TPM_INTF_ID_(x)         TPM_LOC_REG(x, 0x30)
#define INTF_TYPE_MASK           0x0000000fU
#define INTF_TYPE_TIS            0x00
#define INTF_TYPE_CRB            0x01

/*
 * No static caching: the early 32-bit binary (tpm_early.bin) is built with
 * "objcopy -j .text", which omits .bss/.data.
 */
static bool tpm_is_crb(void)
{
    return (tpm_read32(TPM_INTF_ID_(0)) & INTF_TYPE_MASK) == INTF_TYPE_CRB;
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

/************************** CRB register definitions **************************/

#define CRB_LOC_STATE_(x)       TPM_LOC_REG(x, 0x00)
#define CRB_LOC_STATE_LOC_ASSIGNED   (1 << 1)
#define CRB_LOC_STATE_REG_VALID_STS  (1 << 7)
#define CRB_LOC_CTRL_(x)        TPM_LOC_REG(x, 0x08)
#define CRB_LOC_CTRL_REQUEST_ACCESS  (1 << 0)
#define CRB_LOC_CTRL_RELINQUISH      (1 << 1)
#define CRB_CTRL_REQ_(x)        TPM_LOC_REG(x, 0x40)
#define CRB_CTRL_REQ_CMD_READY       (1 << 0)
#define CRB_CTRL_REQ_GO_IDLE         (1 << 1)
#define CRB_CTRL_STS_(x)        TPM_LOC_REG(x, 0x44)
#define CRB_CTRL_STS_ERROR           (1 << 0)
#define CRB_CTRL_CANCEL_(x)     TPM_LOC_REG(x, 0x48)
#define CRB_CTRL_CANCEL_INVOKE       (1 << 0)
#define CRB_CTRL_START_(x)      TPM_LOC_REG(x, 0x4C)
#define CRB_CTRL_START_INVOKE        (1 << 0)
#define CRB_CTRL_CMD_SIZE_(x)   TPM_LOC_REG(x, 0x58)
#define CRB_CTRL_CMD_LADDR_(x)  TPM_LOC_REG(x, 0x5C)
#define CRB_CTRL_CMD_HADDR_(x)  TPM_LOC_REG(x, 0x60)
#define CRB_CTRL_RSP_SIZE_(x)   TPM_LOC_REG(x, 0x64)
#define CRB_CTRL_RSP_ADDR_(x)   TPM_LOC_REG(x, 0x68)
#define CRB_DATA_BUFFER_(x)     TPM_LOC_REG(x, 0x80)
#define CRB_DATA_BUFFER_SIZE    0x0F80

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

/************************** CRB locality & command ****************************/

static void crb_request_locality(unsigned int loc)
{
    const uint32_t mask = CRB_LOC_STATE_LOC_ASSIGNED |
                          CRB_LOC_STATE_REG_VALID_STS;

    tpm_write32(CRB_LOC_CTRL_(loc), CRB_LOC_CTRL_REQUEST_ACCESS);
    while ( (tpm_read32(CRB_LOC_STATE_(loc)) & mask) != mask )
        ;
}

static void crb_relinquish_locality(unsigned int loc)
{
    tpm_write32(CRB_LOC_CTRL_(loc), CRB_LOC_CTRL_RELINQUISH);
    while ( tpm_read32(CRB_LOC_STATE_(loc)) & CRB_LOC_STATE_LOC_ASSIGNED )
        ;
}

static void crb_cmd_ready(unsigned int loc)
{
    tpm_write32(CRB_CTRL_REQ_(loc), CRB_CTRL_REQ_CMD_READY);
    while ( tpm_read32(CRB_CTRL_REQ_(loc)) & CRB_CTRL_REQ_CMD_READY )
        ;
}

static void crb_go_idle(unsigned int loc)
{
    tpm_write32(CRB_CTRL_REQ_(loc), CRB_CTRL_REQ_GO_IDLE);
    while ( tpm_read32(CRB_CTRL_REQ_(loc)) & CRB_CTRL_REQ_GO_IDLE )
        ;
}

static void crb_send_cmd(unsigned int loc, uint8_t *buf, unsigned int i_size,
                         unsigned int *o_size)
{
    paddr_t data_buf_pa = TPM_MMIO_BASE + CRB_DATA_BUFFER_(loc);
    unsigned int expected;

    if ( i_size > CRB_DATA_BUFFER_SIZE || *o_size < sizeof(struct tpm_rsp_hdr) )
    {
        *o_size = 0;
        return;
    }

    /* Out of caution, make sure no previous command is still executing. */
    while ( tpm_read32(CRB_CTRL_START_(loc)) & CRB_CTRL_START_INVOKE )
        ;

    crb_cmd_ready(loc);

    /* In an unlikely event that TPM signals irrecoverable error here,
     * better bail out than hang in infinite loop waiting for the
     * start condition later. */
    if ( tpm_read32(CRB_CTRL_STS_(loc)) & CRB_CTRL_STS_ERROR )
    {
        *o_size = 0;
        crb_go_idle(loc);
        return;
    }

    tpm_write32(CRB_CTRL_CANCEL_(loc), 0);

    tpm_write32(CRB_CTRL_CMD_LADDR_(loc), data_buf_pa);
    tpm_write32(CRB_CTRL_CMD_HADDR_(loc), 0);
    tpm_write32(CRB_CTRL_CMD_SIZE_(loc), CRB_DATA_BUFFER_SIZE);
    tpm_write32(CRB_CTRL_RSP_SIZE_(loc), CRB_DATA_BUFFER_SIZE);
    /* RSP_ADDR is 64-bit. */
    tpm_write32(CRB_CTRL_RSP_ADDR_(loc), data_buf_pa);
    tpm_write32(CRB_CTRL_RSP_ADDR_(loc) + 4, 0);

    memcpy(__va(data_buf_pa), buf, i_size);

    tpm_write32(CRB_CTRL_START_(loc), CRB_CTRL_START_INVOKE);
    while ( tpm_read32(CRB_CTRL_START_(loc)) & CRB_CTRL_START_INVOKE )
        ;

    if ( tpm_read32(CRB_CTRL_STS_(loc)) & CRB_CTRL_STS_ERROR )
    {
        *o_size = 0;
        crb_go_idle(loc);
        return;
    }

    /* Read header to learn the response length. */
    memcpy(buf, __va(data_buf_pa), sizeof(struct tpm_rsp_hdr));
    expected = swap32(((struct tpm_rsp_hdr *)buf)->paramSize);
    if ( expected > *o_size )
        expected = *o_size;
    if ( expected > CRB_DATA_BUFFER_SIZE )
        expected = CRB_DATA_BUFFER_SIZE;

    memcpy(buf, __va(data_buf_pa), expected);

    *o_size = expected;
    crb_go_idle(loc);
}

/************************** Interface dispatch ********************************/

static void request_locality(unsigned int loc)
{
    if ( tpm_is_crb() )
        crb_request_locality(loc);
    else
        tis_request_locality(loc);
}

static void relinquish_locality(unsigned int loc)
{
    if ( tpm_is_crb() )
        crb_relinquish_locality(loc);
    else
        tis_relinquish_locality(loc);
}

static void send_cmd(unsigned int loc, uint8_t *buf, unsigned int i_size,
                     unsigned int *o_size)
{
    if ( tpm_is_crb() )
        crb_send_cmd(loc, buf, i_size, o_size);
    else
        tis_send_cmd(loc, buf, i_size, o_size);
}

bool tpm_is_tpm1(void)
{
    uint32_t intf_version;

    /* CRB interface is always TPM 2.0. */
    if ( tpm_is_crb() )
        return false;

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

/****************************** TPM1.2 & TPM2.0 *******************************/

/*
 * TPM1.2 is required to support commands of up to 1101 bytes, vendors rarely
 * go above that. Limit maximum size of block of data to be hashed to 1024.
 *
 * TPM2.0 should support hashing of at least 1024 bytes.
 */
#define MAX_HASH_BLOCK      1024

/****************************** TPM1.2 specific *******************************/

#ifdef __EARLY_TPM__
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

/****************************** TPM2.0 specific *******************************/

#define PUT_BYTES(p, bytes, size) do {  \
        memcpy(p, bytes, size);         \
        (p) += (size);                  \
    } while ( false )

#define PUT_16BIT(p, data) do {          \
        *(uint16_t *)(p) = swap16(data); \
        (p) += 2;                        \
    } while ( false )

#ifdef __EARLY_TPM__

union tpm2_cmd_rsp {
    uint8_t b[sizeof(struct tpm2_sequence_update_cmd) + MAX_HASH_BLOCK];
    struct tpm_cmd_hdr c;
    struct tpm_rsp_hdr r;
    struct tpm2_sequence_start_cmd start_c;
    struct tpm2_sequence_start_rsp start_r;
    struct tpm2_sequence_update_cmd update_c;
    struct tpm2_sequence_update_rsp update_r;
    struct tpm2_sequence_complete_cmd finish_c;
    struct tpm2_sequence_complete_rsp finish_r;
};

static uint32_t tpm2_hash_extend(unsigned int loc, const uint8_t *buf,
                                 unsigned int size, unsigned int pcr,
                                 const struct tpm_log_hashes *log_hashes)
{
    uint32_t seq_handle;
    unsigned int max_bytes = MAX_HASH_BLOCK;

    union tpm2_cmd_rsp cmd_rsp;
    unsigned int o_size;
    unsigned int i;
    uint8_t *p;
    uint32_t rc;

    cmd_rsp.start_c = (struct tpm2_sequence_start_cmd) {
        .h.tag = swap16(TPM_ST_NO_SESSIONS),
        .h.paramSize = swap32(sizeof(cmd_rsp.start_c)),
        .h.ordinal = swap32(TPM2_PCR_HashSequenceStart),
        .hashAlg = swap16(TPM_ALG_NULL), /* Compute all supported hashes. */
    };

    request_locality(loc);

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    if ( o_size < sizeof(struct tpm_rsp_hdr) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    seq_handle = swap32(cmd_rsp.start_r.sequenceHandle);

    while ( size > 64 )
    {
        if ( size < max_bytes )
            max_bytes = ROUNDDOWN(size, 64);

        cmd_rsp.update_c = (struct tpm2_sequence_update_cmd) {
            .h.tag = swap16(TPM_ST_SESSIONS),
            .h.paramSize = swap32(sizeof(cmd_rsp.update_c) + max_bytes),
            .h.ordinal = swap32(TPM2_PCR_SequenceUpdate),
            .sequenceHandle = swap32(seq_handle),
            .sessionHdrSize = swap32(sizeof(struct tpm2_session_header)),
            .session.handle = swap32(TPM_RS_PW),
            .dataSize = swap16(max_bytes),
        };

        memcpy(cmd_rsp.update_c.data, buf, max_bytes);

        o_size = sizeof(cmd_rsp);
        send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

        if ( o_size < sizeof(struct tpm_rsp_hdr) )
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

    cmd_rsp.finish_c = (struct tpm2_sequence_complete_cmd) {
        .h.tag = swap16(TPM_ST_SESSIONS),
        .h.paramSize = swap32(sizeof(cmd_rsp.finish_c) + size),
        .h.ordinal = swap32(TPM2_PCR_EventSequenceComplete),
        .pcrHandle = swap32(HR_PCR + pcr),
        .sequenceHandle = swap32(seq_handle),
        .sessionHdrSize = swap32(sizeof(struct tpm2_session_header) * 2),
        .pcrSession.handle = swap32(TPM_RS_PW),
        .sequenceSession.handle = swap32(TPM_RS_PW),
        .dataSize = swap16(size),
    };

    memcpy(cmd_rsp.finish_c.data, buf, size);

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    if ( o_size < sizeof(struct tpm_rsp_hdr) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    if ( o_size < sizeof(cmd_rsp.finish_r) )
    {
        rc = TPM_INTERNAL_ERROR;
        goto error;
    }

    p = cmd_rsp.finish_r.hashes;
    for ( i = 0; i < swap32(cmd_rsp.finish_r.hashCount); ++i )
    {
        unsigned int j;
        uint16_t hash_type;

        if ( p + sizeof(uint16_t) > cmd_rsp.b + o_size )
        {
            rc = TPM_INTERNAL_ERROR;
            goto error;
        }
        hash_type = swap16(*(uint16_t *)p);
        p += sizeof(uint16_t);

        for ( j = 0; j < log_hashes->count; ++j )
        {
            const struct tpm_log_hash *hash = &log_hashes->hashes[j];
            if ( hash->alg == hash_type )
            {
                if ( p + hash->size > cmd_rsp.b + o_size )
                {
                    rc = TPM_INTERNAL_ERROR;
                    goto error;
                }
                memcpy(hash->data, p, hash->size);
                p += hash->size;
                break;
            }
        }

        if ( j == log_hashes->count )
            /* Can't continue parsing without knowing hash size. */
            break;
    }

    rc = 0;

 error:
    relinquish_locality(loc);
    return rc;
}

#else

union tpm2_cmd_rsp {
    /* Enough space for multiple hashes. */
    uint8_t b[sizeof(struct tpm2_extend_cmd) + 1024];
    struct tpm_cmd_hdr c;
    struct tpm_rsp_hdr r;
    struct tpm2_extend_cmd extend_c;
    struct tpm2_extend_rsp extend_r;
};

static uint32_t tpm20_pcr_extend(unsigned int loc, uint32_t pcr_handle,
                                 const struct tpm_log_hashes *log_hashes)
{
    union tpm2_cmd_rsp cmd_rsp;
    unsigned int o_size;
    unsigned int i;
    uint8_t *p;

    cmd_rsp.extend_c = (struct tpm2_extend_cmd) {
        .h.tag = swap16(TPM_ST_SESSIONS),
        .h.ordinal = swap32(TPM2_PCR_Extend),
        .pcrHandle = swap32(pcr_handle),
        .sessionHdrSize = swap32(sizeof(struct tpm2_session_header)),
        .pcrSession.handle = swap32(TPM_RS_PW),
        .hashCount = swap32(log_hashes->count),
    };

    p = cmd_rsp.extend_c.hashes;
    for ( i = 0; i < log_hashes->count; ++i )
    {
        const struct tpm_log_hash *hash = &log_hashes->hashes[i];

        if ( p + sizeof(uint16_t) + hash->size > &cmd_rsp.b[sizeof(cmd_rsp)] )
        {
            printk(XENLOG_ERR "Hit TPM message size implementation limit: %ld\n",
                   sizeof(cmd_rsp));
            return TPM_INTERNAL_ERROR;
        }

        *(uint16_t *)p = swap16(hash->alg);
        p += sizeof(uint16_t);

        memcpy(p, hash->data, hash->size);
        p += hash->size;
    }

    /* Fill in command size (size of the whole buffer). */
    cmd_rsp.c.paramSize = swap32(sizeof(cmd_rsp.extend_c) +
                                 (p - cmd_rsp.extend_c.hashes));

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    return swap32(cmd_rsp.r.returnCode);
}

static bool tpm2_supports_hash(unsigned int loc,
                               const struct tpm_log_hash *hash)
{
    uint32_t rc;
    struct tpm_log_hashes hashes = {
        .count = 1,
        .hashes[0] = *hash,
    };

    /*
     * This is a valid way of checking hash support, using it to not implement
     * TPM2_GetCapability().
     */
    rc = tpm20_pcr_extend(loc, /*pcr_handle=*/TPM_RH_NULL, &hashes);

    return rc == 0;
}

static uint32_t tpm2_hash_extend(unsigned int loc, const uint8_t *buf,
                                 unsigned int size, unsigned int pcr,
                                 const struct tpm_log_hashes *log_hashes)
{
    uint32_t rc;
    unsigned int i;
    struct tpm_log_hashes supported_hashes = {0};

    request_locality(loc);

    for ( i = 0; i < log_hashes->count; ++i )
    {
        const struct tpm_log_hash *hash = &log_hashes->hashes[i];
        if ( !tpm2_supports_hash(loc, hash) )
        {
            printk(XENLOG_WARNING "Skipped hash unsupported by TPM: %d\n",
                   hash->alg);
            continue;
        }

        if ( hash->alg == TPM_ALG_SHA1 )
        {
            sha1(hash->data, buf, size);
        }
        else if ( hash->alg == TPM_ALG_SHA256 )
        {
            sha2_256(hash->data, buf, size);
        }
        else
        {
            /*
             * Assuming the caller has initialized the digest with some
             * pattern.
             */
        }

        if ( supported_hashes.count == MAX_TPM_HASH_COUNT )
        {
            printk(XENLOG_ERR "Hit hash count implementation limit: %d\n",
                   MAX_TPM_HASH_COUNT);
            return TPM_INTERNAL_ERROR;
        }

        supported_hashes.hashes[supported_hashes.count] = *hash;
        ++supported_hashes.count;
    }

    rc = tpm20_pcr_extend(loc, HR_PCR + pcr, &supported_hashes);
    relinquish_locality(loc);

    return rc;
}

#endif /* __EARLY_TPM__ */

/************************** end of TPM2.0 specific ****************************/

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

    return tpm2_hash_extend(loc, buf, size, pcr, log_hashes);
}
