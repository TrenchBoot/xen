/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/sha1.h>
#include <xen/sha2.h>
#include <xen/string.h>
#include <xen/types.h>

#include <asm/intel-txt.h>
#include <asm/slaunch.h>
#include <asm/tpm.h>
#include <asm/tpm1.h>
#include <asm/tpm2.h>
#include <asm/x86-vendors.h>

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
void *(memset)(void *s, int c, size_t n)
{
    uint8_t *d = s;

    while ( n-- )
        *d++ = c;

    return s;
}
void *(memcpy)(void *dest, const void *src, size_t n)
{
    const uint8_t *s = src;
    uint8_t *d = dest;

    while ( n-- )
        *d++ = *s++;

    return dest;
}

static bool is_amd_cpu(void)
{
    /*
     * asm/processor.h can't be included in early code, which means neither
     * cpuid() function nor boot_cpu_data can be used here.
     */
    uint32_t eax, ebx, ecx, edx;
    asm volatile ( "cpuid"
          : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
          : "0" (0), "c" (0) );
    return ebx == X86_VENDOR_AMD_EBX
        && ecx == X86_VENDOR_AMD_ECX
        && edx == X86_VENDOR_AMD_EDX;
}

#else   /* __EARLY_SLAUNCH__ */

#include <xen/mm.h>
#include <xen/pfn.h>

static bool is_amd_cpu(void)
{
    return boot_cpu_data.x86_vendor == X86_VENDOR_AMD;
}

#endif  /* __EARLY_SLAUNCH__ */

#define TPM_LOC_REG(loc, reg)   (0x1000 * (loc) + (reg))

#define swap16(x)       __builtin_bswap16(x)
#define swap32(x)       __builtin_bswap32(x)

/******************************** MMIO helpers ********************************/

static inline uint32_t tpm_read32(unsigned reg)
{
    return *(volatile uint32_t *)__va(TPM_BASE + reg);
}

static inline uint16_t tpm_read16(unsigned reg)
{
    return *(volatile uint16_t *)__va(TPM_BASE + reg);
}

static inline uint8_t tpm_read8(unsigned reg)
{
    return *(volatile uint8_t *)__va(TPM_BASE + reg);
}

static inline void tpm_write32(unsigned reg, uint32_t val)
{
    *(volatile uint32_t *)__va(TPM_BASE + reg) = val;
}

static inline void tpm_write8(unsigned reg, uint8_t val)
{
    *(volatile uint8_t *)__va(TPM_BASE + reg) = val;
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
static inline bool tpm_is_crb(void)
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
#define TIS_BURST_COUNT_(x)     TPM_LOC_REG(x, 0x19)
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

static inline void tis_request_locality(unsigned loc)
{
    tpm_write8(TIS_ACCESS_(loc), ACCESS_REQUEST_USE);
    /* Check that locality was actually activated. */
    while ( (tpm_read8(TIS_ACCESS_(loc)) & ACCESS_ACTIVE_LOCALITY) == 0 );
}

static inline void tis_relinquish_locality(unsigned loc)
{
    tpm_write8(TIS_ACCESS_(loc), ACCESS_ACTIVE_LOCALITY);
}

static inline uint16_t tis_get_burst_count(unsigned loc)
{
    return tpm_read16(TIS_BURST_COUNT_(loc));
}

static void tis_send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                         unsigned *o_size)
{
    /*
     * Values of "expect data" and "data available" bits counts only when
     * "valid" field is set as well.
     */
    const unsigned expect_data = STS_VALID | STS_EXPECT_DATA;
    const unsigned data_avail = STS_VALID | STS_DATA_AVAIL;

    unsigned i;
    unsigned burst_count;

    /* Make sure TPM can accept a command. */
    if ( (tpm_read8(TIS_STS_(loc)) & STS_COMMAND_READY) == 0 )
    {
        /* Abort current command. */
        tpm_write8(TIS_STS_(loc), STS_COMMAND_READY);
        /* Wait until TPM is ready for a new one. */
        while ( (tpm_read8(TIS_STS_(loc)) & STS_COMMAND_READY) == 0 );
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
            while ( (tpm_read8(TIS_STS_(loc)) & expect_data) != expect_data );
    }

    tpm_write8(TIS_STS_(loc), STS_TPM_GO);

    /* Wait for the first byte of response. */
    while ( (tpm_read8(TIS_STS_(loc)) & data_avail) != data_avail );

    i = 0;
    do {
        do
            burst_count = tis_get_burst_count(loc);
        while ( burst_count == 0 );

        while ( burst_count-- > 0 && i < *o_size)
            buf[i++] = tpm_read8(TIS_DATA_FIFO_(loc));

        while ( (tpm_read8(TIS_STS_(loc)) & STS_VALID) == 0 );
    } while ( i < *o_size &&
              (tpm_read8(TIS_STS_(loc)) & data_avail) == data_avail );

    if ( i < *o_size )
        *o_size = i;

    tpm_write8(TIS_STS_(loc), STS_COMMAND_READY);
}

/************************** CRB locality & command ****************************/

static void crb_request_locality(unsigned loc)
{
    const uint32_t mask = CRB_LOC_STATE_LOC_ASSIGNED |
                          CRB_LOC_STATE_REG_VALID_STS;

    tpm_write32(CRB_LOC_CTRL_(loc), CRB_LOC_CTRL_REQUEST_ACCESS);
    while ( (tpm_read32(CRB_LOC_STATE_(loc)) & mask) != mask );
}

static void crb_relinquish_locality(unsigned loc)
{
    tpm_write32(CRB_LOC_CTRL_(loc), CRB_LOC_CTRL_RELINQUISH);
    while ( tpm_read32(CRB_LOC_STATE_(loc)) & CRB_LOC_STATE_LOC_ASSIGNED );
}

static void crb_cmd_ready(unsigned loc)
{
    tpm_write32(CRB_CTRL_REQ_(loc), CRB_CTRL_REQ_CMD_READY);
    while ( tpm_read32(CRB_CTRL_REQ_(loc)) & CRB_CTRL_REQ_CMD_READY );
}

static void crb_go_idle(unsigned loc)
{
    tpm_write32(CRB_CTRL_REQ_(loc), CRB_CTRL_REQ_GO_IDLE);
    while ( tpm_read32(CRB_CTRL_REQ_(loc)) & CRB_CTRL_REQ_GO_IDLE );
}

static void crb_send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                         unsigned *o_size)
{
    paddr_t data_buf_pa = TPM_BASE + CRB_DATA_BUFFER_(loc);
    unsigned expected;

    if ( i_size > CRB_DATA_BUFFER_SIZE ||
         *o_size < sizeof(struct tpm_rsp_hdr) )
    {
        *o_size = 0;
        return;
    }

    /* Out of caution, make sure no previous command is still executing. */
    while ( tpm_read32(CRB_CTRL_START_(loc)) & CRB_CTRL_START_INVOKE );

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
    while ( tpm_read32(CRB_CTRL_START_(loc)) & CRB_CTRL_START_INVOKE );

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

static inline void request_locality(unsigned loc)
{
    if ( tpm_is_crb() )
        crb_request_locality(loc);
    else
        tis_request_locality(loc);
}

static inline void relinquish_locality(unsigned loc)
{
    if ( tpm_is_crb() )
        crb_relinquish_locality(loc);
    else
        tis_relinquish_locality(loc);
}

static void send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                     unsigned *o_size)
{
    if ( tpm_is_crb() )
        crb_send_cmd(loc, buf, i_size, o_size);
    else
        tis_send_cmd(loc, buf, i_size, o_size);
}

static inline bool is_tpm12(void)
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
            (tpm_read32(TIS_STS_(0)) & STS_FAMILY_MASK) == 0);
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

#ifdef __EARLY_SLAUNCH__
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

    if ( is_amd_cpu() )
    {
        /*
         * On AMD, TXT-compatible structure is stored as vendor data of
         * TCG-defined event log header.
         */
        struct tpm1_spec_id_event *spec_id = (void *)evt_log;
        evt_log = (struct txt_ev_log_container_12 *)&spec_id->vendorInfo[0];
    }

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

/****************************** TPM2.0 specific *******************************/

#define PUT_BYTES(p, bytes, size)  do {  \
        memcpy((p), (bytes), (size));    \
        (p) += (size);                   \
    } while ( 0 )

#define PUT_16BIT(p, data) do {          \
        *(uint16_t *)(p) = swap16(data); \
        (p) += 2;                        \
    } while ( 0 )

/*
 * These two structures are for convenience, they don't correspond to anything
 * in any specification.
 */
struct tpm2_log_hash {
    uint16_t alg;  /* TPM_ALG_* */
    uint16_t size;
    uint8_t *data; /* Non-owning reference to a buffer inside log entry. */
};
/* Should be more than enough for now and awhile in the future. */
#define MAX_HASH_COUNT 8
struct tpm2_log_hashes {
    uint32_t count;
    struct tpm2_log_hash hashes[MAX_HASH_COUNT];
};

#ifdef __EARLY_SLAUNCH__

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

static uint32_t tpm2_hash_extend(unsigned loc, const uint8_t *buf,
                                 unsigned size, unsigned pcr,
                                 struct tpm2_log_hashes *log_hashes)
{
    uint32_t seq_handle;
    unsigned max_bytes = MAX_HASH_BLOCK;

    union tpm2_cmd_rsp cmd_rsp;
    unsigned o_size;
    unsigned i;
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
        rc = -1;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    seq_handle = swap32(cmd_rsp.start_r.sequenceHandle);

    while ( size > 64 )
    {
        if ( size < max_bytes )
            max_bytes = size & ~(64 - 1);

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
            rc = -1;
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
        .sessionHdrSize = swap32(sizeof(struct tpm2_session_header)*2),
        .pcrSession.handle = swap32(TPM_RS_PW),
        .sequenceSession.handle = swap32(TPM_RS_PW),
        .dataSize = swap16(size),
    };

    memcpy(cmd_rsp.finish_c.data, buf, size);

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    if ( o_size < sizeof(struct tpm_rsp_hdr) )
    {
        rc = -1;
        goto error;
    }
    rc = swap32(cmd_rsp.r.returnCode);
    if ( rc != 0 )
        goto error;

    if ( o_size < sizeof(cmd_rsp.finish_r) )
    {
        rc = -1;
        goto error;
    }

    p = cmd_rsp.finish_r.hashes;
    for ( i = 0; i < swap32(cmd_rsp.finish_r.hashCount); ++i )
    {
        unsigned j;
        uint16_t hash_type;

        if ( p + sizeof(uint16_t) > cmd_rsp.b + o_size )
        {
            rc = -1;
            goto error;
        }
        hash_type = swap16(*(uint16_t *)p);
        p += sizeof(uint16_t);

        for ( j = 0; j < log_hashes->count; ++j )
        {
            struct tpm2_log_hash *hash = &log_hashes->hashes[j];
            if ( hash->alg == hash_type )
            {
                if ( p + hash->size > cmd_rsp.b + o_size )
                {
                    rc = -1;
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

static uint32_t tpm20_pcr_extend(unsigned loc, uint32_t pcr_handle,
                                 const struct tpm2_log_hashes *log_hashes)
{
    union tpm2_cmd_rsp cmd_rsp;
    unsigned o_size;
    unsigned i;
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
        const struct tpm2_log_hash *hash = &log_hashes->hashes[i];

        if ( p + sizeof(uint16_t) + hash->size > &cmd_rsp.b[sizeof(cmd_rsp)] )
        {
            printk(XENLOG_ERR "Hit TPM message size implementation limit: %ld\n",
                   sizeof(cmd_rsp));
            return -1;
        }

        *(uint16_t *)p = swap16(hash->alg);
        p += sizeof(uint16_t);

        memcpy(p, hash->data, hash->size);
        p += hash->size;
    }

    /* Fill in command size (size of the whole buffer). */
    cmd_rsp.extend_c.h.paramSize = swap32(sizeof(cmd_rsp.extend_c) +
                                          (p - cmd_rsp.extend_c.hashes)),

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    return swap32(cmd_rsp.r.returnCode);
}

static bool tpm_supports_hash(unsigned loc, const struct tpm2_log_hash *hash)
{
    uint32_t rc;
    struct tpm2_log_hashes hashes = {
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

static uint32_t tpm2_hash_extend(unsigned loc, const uint8_t *buf,
                                 unsigned size, unsigned pcr,
                                 const struct tpm2_log_hashes *log_hashes)
{
    uint32_t rc;
    unsigned i;
    struct tpm2_log_hashes supported_hashes = {0};

    request_locality(loc);

    for ( i = 0; i < log_hashes->count; ++i )
    {
        const struct tpm2_log_hash *hash = &log_hashes->hashes[i];
        if ( !tpm_supports_hash(loc, hash) )
        {
            printk(XENLOG_WARNING "Skipped hash unsupported by TPM: %d\n",
                   hash->alg);
            continue;
        }

        if ( hash->alg == TPM_ALG_SHA1 )
            sha1(hash->data, buf, size);
        else if ( hash->alg == TPM_ALG_SHA256 )
            sha2_256(hash->data, buf, size);
        else
            /* create_log_event20() took care of initializing the digest. */;

        if ( supported_hashes.count == MAX_HASH_COUNT )
        {
            printk(XENLOG_ERR "Hit hash count implementation limit: %d\n",
                   MAX_HASH_COUNT);
            return -1;
        }

        supported_hashes.hashes[supported_hashes.count] = *hash;
        ++supported_hashes.count;
    }

    rc = tpm20_pcr_extend(loc, HR_PCR + pcr, &supported_hashes);
    relinquish_locality(loc);

    return rc;
}

#endif /* __EARLY_SLAUNCH__ */

static struct heap_event_log_pointer_element2_1 *
find_evt_log_ext_data(struct tpm2_spec_id_event *evt_log)
{
    struct txt_os_sinit_data *os_sinit;
    struct txt_ext_data_element *ext_data;

    if ( is_amd_cpu() )
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

static struct tpm2_log_hashes
create_log_event20(struct tpm2_spec_id_event *evt_log, uint32_t evt_log_size,
                   uint32_t pcr, uint32_t type, const uint8_t *data,
                   unsigned data_size)
{
    struct tpm2_log_hashes log_hashes = {0};

    struct heap_event_log_pointer_element2_1 *log_ext_data;
    struct tpm2_pcr_event_header *new_entry;
    uint32_t entry_size;
    unsigned i;
    uint8_t *p;

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

    new_entry = (void *)((uint8_t *)evt_log + log_ext_data->next_record_offset);
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

    if ( data && data_size > 0 )
        memcpy(p, data, data_size);

    return log_hashes;
}

/************************** end of TPM2.0 specific ****************************/

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
    else
    {
        uint32_t rc;

        struct tpm2_spec_id_event *evt_log = __va(evt_log_paddr);
        struct tpm2_log_hashes log_hashes =
            create_log_event20(evt_log, evt_log_size, pcr, type, log_data,
                               log_data_size);

        rc = tpm2_hash_extend(loc, buf, size, pcr, &log_hashes);
        if ( rc != 0 )
        {
#ifndef __EARLY_SLAUNCH__
            printk(XENLOG_ERR "Extending PCR%u failed with TPM error: 0x%08x\n",
                   pcr, rc);
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
