/*
 * Copyright (c) 2022 3mdeb Sp. z o.o. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef __EARLY_TPM__
/*
 * This entry point is entered from xen/arch/x86/boot/head.S with MBI base at
 * 0x4(%esp).
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  tpm_extend_mbi           \n"
    );

#include "boot/defs.h"
#include "include/asm/intel_txt.h"
#ifdef __va
#error "__va defined in non-paged mode!"
#endif
#define __va(x)     _p(x)

void *memcpy(void *dest, const void *src, size_t n)
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
#include <xen/types.h>
#include <asm/intel_txt.h>

void sha1_hash(const uint8_t message[], size_t len,
               uint32_t hash[static SHA1_DIGEST_SIZE/sizeof(uint32_t)]);
void sha256_hash(const uint8_t message[], size_t len,
                 uint32_t hash[static SHA256_DIGEST_SIZE/sizeof(uint32_t)]);

#endif  /* __EARLY_TPM__ */

#define TPM_TIS_BASE            0xFED40000
#define TPM_LOC_REG(loc, reg)   (0x1000 * (loc) + (reg))

#define TPM_ACCESS_(x)          TPM_LOC_REG(x, 0x00)
#define ACCESS_REQUEST_USE       (1 << 1)
#define ACCESS_ACTIVE_LOCALITY   (1 << 5)
#define TPM_INTF_CAPABILITY_(x) TPM_LOC_REG(x, 0x14)
#define INTF_VERSION_MASK        0x70000000
#define TPM_STS_(x)             TPM_LOC_REG(x, 0x18)
#define TPM_FAMILY_MASK          0x0C000000
#define STS_DATA_AVAIL           (1 << 4)
#define STS_TPM_GO               (1 << 5)
#define STS_COMMAND_READY        (1 << 6)
#define STS_VALID                (1 << 7)
#define TPM_DATA_FIFO_(x)       TPM_LOC_REG(x, 0x24)

#define swap16(x)       __builtin_bswap16(x)
#define swap32(x)       __builtin_bswap32(x)
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)

static inline volatile uint32_t tis_read32(unsigned reg)
{
    return *(volatile uint32_t *)__va(TPM_TIS_BASE + reg);
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

static void send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                     unsigned *o_size)
{
    /*
     * Value of "data available" bit counts only when "valid" field is set as
     * well.
     */
    const unsigned data_avail = STS_VALID | STS_DATA_AVAIL;

    unsigned i;

    /* Make sure TPM can accept a command. */
    if ( (tis_read8(TPM_STS_(loc)) & STS_COMMAND_READY) == 0 ) {
        /* Abort current command. */
        tis_write8(TPM_STS_(loc), STS_COMMAND_READY);
        /* Wait until TPM is ready for a new one. */
        while ( (tis_read8(TPM_STS_(loc)) & STS_COMMAND_READY) == 0 );
    }

    for ( i = 0; i < i_size; i++ )
        tis_write8(TPM_DATA_FIFO_(loc), buf[i]);

    tis_write8(TPM_STS_(loc), STS_TPM_GO);

    /* Wait for the first byte of response. */
    while ( (tis_read8(TPM_STS_(loc)) & data_avail) != data_avail);

    for ( i = 0; i < *o_size && tis_read8(TPM_STS_(loc)) & data_avail; i++ )
        buf[i] = tis_read8(TPM_DATA_FIFO_(loc));

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

static inline void find_evt_log(void **evt_log, uint32_t *evt_log_size)
{
    struct txt_os_mle_data *os_mle;
    os_mle = txt_os_mle_data_start(__va(read_txt_reg(TXTCR_HEAP_BASE)));

    *evt_log = __va(os_mle->evtlog_addr);
    *evt_log_size = os_mle->evtlog_size;
}

/****************************** TPM1.2 & TPM2.0 *******************************/

/*
 * TPM1.2 is required to support commands of up to 1101 bytes, vendors rarely
 * go above that. Limit maximum size of block of data to be hashed to 1024.
 *
 * TPM2.0 should support hashing of at least 1024 bytes.
 */
#define MAX_HASH_BLOCK      1024

/* All fields of following structs are big endian. */
struct tpm_cmd_hdr {
    uint16_t    tag;
    uint32_t    paramSize;
    uint32_t    ordinal;
} __packed;

struct tpm_rsp_hdr {
    uint16_t    tag;
    uint32_t    paramSize;
    uint32_t    returnCode;
} __packed;

/****************************** TPM1.2 specific *******************************/

#define TPM_ORD_Extend              0x00000014
#define TPM_ORD_SHA1Start           0x000000A0
#define TPM_ORD_SHA1Update          0x000000A1
#define TPM_ORD_SHA1CompleteExtend  0x000000A3

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RSP_COMMAND         0x00C4

/* All fields of following structs are big endian. */
struct extend_cmd {
    struct tpm_cmd_hdr h;
    uint32_t pcrNum;
    uint8_t inDigest[SHA1_DIGEST_SIZE];
} __packed;

struct extend_rsp {
    struct tpm_rsp_hdr h;
    uint8_t outDigest[SHA1_DIGEST_SIZE];
} __packed;

struct sha1_start_cmd {
    struct tpm_cmd_hdr h;
} __packed;

struct sha1_start_rsp {
    struct tpm_rsp_hdr h;
    uint32_t maxNumBytes;
} __packed;

struct sha1_update_cmd {
    struct tpm_cmd_hdr h;
    uint32_t numBytes;          /* Must be a multiple of 64 */
    uint8_t hashData[];
} __packed;

struct sha1_update_rsp {
    struct tpm_rsp_hdr h;
} __packed;

struct sha1_complete_extend_cmd {
    struct tpm_cmd_hdr h;
    uint32_t pcrNum;
    uint32_t hashDataSize;      /* 0-64, inclusive */
    uint8_t hashData[];
} __packed;

struct sha1_complete_extend_rsp {
    struct tpm_rsp_hdr h;
    uint8_t hashValue[SHA1_DIGEST_SIZE];
    uint8_t outDigest[SHA1_DIGEST_SIZE];
} __packed;

struct TPM12_PCREvent {
    uint32_t PCRIndex;
    uint32_t Type;
    uint8_t Digest[SHA1_DIGEST_SIZE];
    uint32_t Size;
    uint8_t Data[];
};

struct txt_ev_log_container_12 {
    char        Signature[20];      /* "TXT Event Container", null-terminated */
    uint8_t     Reserved[12];
    uint8_t     ContainerVerMajor;
    uint8_t     ContainerVerMinor;
    uint8_t     PCREventVerMajor;
    uint8_t     PCREventVerMinor;
    uint32_t    ContainerSize;      /* Allocated size */
    uint32_t    PCREventsOffset;
    uint32_t    NextEventOffset;
    struct TPM12_PCREvent   PCREvents[];
};

#ifdef __EARLY_TPM__
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

static void tpm_hash_extend12(unsigned loc, uint8_t *buf, unsigned size,
                              unsigned pcr, uint8_t *out_digest)
{
    union cmd_rsp cmd_rsp;
    unsigned max_bytes = MAX_HASH_BLOCK;
    unsigned o_size = sizeof(cmd_rsp);

    request_locality(loc);

    cmd_rsp.start_c = (struct sha1_start_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct sha1_start_cmd)),
        .h.ordinal = swap32(TPM_ORD_SHA1Start),
    };

    send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_start_cmd), &o_size);

    // assert (o_size >= sizeof(struct sha1_start_rsp));

    if ( max_bytes > swap32(cmd_rsp.start_r.maxNumBytes) )
        max_bytes = swap32(cmd_rsp.start_r.maxNumBytes);

    while ( size > 64 ) {
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

        // assert (o_size >= sizeof(struct sha1_update_rsp));

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

    // assert (o_size >= sizeof(struct sha1_complete_extend_rsp));

    relinquish_locality(loc);

    if ( out_digest != NULL )
        memcpy(out_digest, cmd_rsp.finish_r.hashValue, SHA1_DIGEST_SIZE);
}

#else

union cmd_rsp {
    struct extend_cmd extend_c;
    struct extend_rsp extend_r;
};

static void tpm_hash_extend12(unsigned loc, uint8_t *buf, unsigned size,
                              unsigned pcr, uint8_t *out_digest)
{
    union cmd_rsp cmd_rsp;
    unsigned o_size = sizeof(cmd_rsp);

    sha1_hash(buf, size, (uint32_t *)out_digest);

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
}

#endif /* __EARLY_TPM__ */

static void *create_log_event12(struct txt_ev_log_container_12 *evt_log,
                                uint32_t evt_log_size, uint32_t pcr,
                                uint32_t type, uint8_t *data,
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

/****************************** TPM2.0 specific *******************************/

/*
 * These constants are for TPM2.0 but don't have a distinct prefix to match
 * names in the specification.
 */

#define TPM_HT_PCR   0x00

#define TPM_RH_NULL  0x40000007
#define TPM_RS_PW    0x40000009

#define HR_SHIFT     24
#define HR_PCR       (TPM_HT_PCR << HR_SHIFT)

#define TPM_ST_NO_SESSIONS  0x8001
#define TPM_ST_SESSIONS     0x8002

#define TPM_ALG_SHA1        0x0004
#define TPM_ALG_SHA256      0x000b
#define TPM_ALG_NULL        0x0010

#define TPM2_PCR_Extend                 0x00000182
#define TPM2_PCR_HashSequenceStart      0x00000186
#define TPM2_PCR_SequenceUpdate         0x0000015C
#define TPM2_PCR_EventSequenceComplete  0x00000185

#define PUT_BYTES(p, bytes, size)  do {  \
        memcpy((p), (bytes), (size));    \
        (p) += (size);                   \
    } while ( 0 )

#define PUT_16BIT(p, data) do {          \
        *(uint16_t *)(p) = swap16(data); \
        (p) += 2;                        \
    } while ( 0 )

/* All fields of following structs are big endian. */
struct tpm2_session_header {
    uint32_t handle;
    uint16_t nonceSize;
    uint8_t nonce[0];
    uint8_t attrs;
    uint16_t hmacSize;
    uint8_t hmac[0];
} __packed;

struct tpm2_extend_cmd {
    struct tpm_cmd_hdr h;
    uint32_t pcrHandle;
    uint32_t sessionHdrSize;
    struct tpm2_session_header pcrSession;
    uint32_t hashCount;
    uint8_t hashes[0];
} __packed;

struct tpm2_extend_rsp {
    struct tpm_rsp_hdr h;
} __packed;

struct tpm2_sequence_start_cmd {
    struct tpm_cmd_hdr h;
    uint16_t hmacSize;
    uint8_t hmac[0];
    uint16_t hashAlg;
} __packed;

struct tpm2_sequence_start_rsp {
    struct tpm_rsp_hdr h;
    uint32_t sequenceHandle;
} __packed;

struct tpm2_sequence_update_cmd {
    struct tpm_cmd_hdr h;
    uint32_t sequenceHandle;
    uint32_t sessionHdrSize;
    struct tpm2_session_header session;
    uint16_t dataSize;
    uint8_t data[0];
} __packed;

struct tpm2_sequence_update_rsp {
    struct tpm_rsp_hdr h;
} __packed;

struct tpm2_sequence_complete_cmd {
    struct tpm_cmd_hdr h;
    uint32_t pcrHandle;
    uint32_t sequenceHandle;
    uint32_t sessionHdrSize;
    struct tpm2_session_header pcrSession;
    struct tpm2_session_header sequenceSession;
    uint16_t dataSize;
    uint8_t data[0];
} __packed;

struct tpm2_sequence_complete_rsp {
    struct tpm_rsp_hdr h;
    uint32_t paramSize;
    uint32_t hashCount;
    uint8_t hashes[0];
    /*
     * Each hash is represented as:
     * struct {
     *     uint16_t hashAlg;
     *     uint8_t hash[size of hashAlg];
     * };
     */
} __packed;

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

static uint32_t tpm_hash_extend20(unsigned loc, uint8_t *buf, unsigned size,
                                  unsigned pcr, uint8_t *sha1_digest,
                                  uint8_t *sha256_digest)
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

    if ( cmd_rsp.r.tag == swap16(TPM_ST_NO_SESSIONS) &&
         cmd_rsp.r.paramSize == swap32(10) ) {
        rc = swap32(cmd_rsp.r.returnCode);
        if ( rc != 0 )
            goto error;
    }

    seq_handle = swap32(cmd_rsp.start_r.sequenceHandle);

    while ( size > 64 ) {
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

        if ( cmd_rsp.r.tag == swap16(TPM_ST_NO_SESSIONS) &&
             cmd_rsp.r.paramSize == swap32(10) ) {
            rc = swap32(cmd_rsp.r.returnCode);
            if ( rc != 0 )
                goto error;
        }

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

    if ( cmd_rsp.r.tag == swap16(TPM_ST_NO_SESSIONS) &&
         cmd_rsp.r.paramSize == swap32(10) ) {
        rc = swap32(cmd_rsp.r.returnCode);
        if ( rc != 0 )
            goto error;
    }

    p = cmd_rsp.finish_r.hashes;
    for ( i = 0; i < swap32(cmd_rsp.finish_r.hashCount); ++i ) {
        uint16_t hash_type;

        hash_type = swap16(*(uint16_t *)p);
        p += sizeof(uint16_t);

        if ( hash_type == TPM_ALG_SHA1 ) {
            if ( sha1_digest != NULL)
                memcpy(sha1_digest, p, SHA1_DIGEST_SIZE);
            p += SHA1_DIGEST_SIZE;
        } else if ( hash_type == TPM_ALG_SHA256 ) {
            if ( sha256_digest != NULL)
                memcpy(sha256_digest, p, SHA256_DIGEST_SIZE);
            p += SHA256_DIGEST_SIZE;
        } else {
            break;
        }
    }

    rc = 0;

error:
    relinquish_locality(loc);
    return rc;
}

#else

union tpm2_cmd_rsp {
    /* Enough for a couple of hashes. */
    uint8_t b[sizeof(struct tpm2_extend_cmd) + 64];
    struct tpm_cmd_hdr c;
    struct tpm_rsp_hdr r;
    struct tpm2_extend_cmd extend_c;
    struct tpm2_extend_rsp extend_r;
};

static uint32_t tpm20_pcr_extend(unsigned loc, uint32_t pcr_handle,
                                 const uint8_t *sha1_digest,
                                 const uint8_t *sha256_digest)
{
    union tpm2_cmd_rsp cmd_rsp;
    unsigned o_size;
    unsigned hash_count;
    uint8_t *p;

    cmd_rsp.extend_c = (struct tpm2_extend_cmd) {
        .h.tag = swap16(TPM_ST_SESSIONS),
        .h.ordinal = swap32(TPM2_PCR_Extend),
        .pcrHandle = swap32(pcr_handle),
        .sessionHdrSize = swap32(sizeof(struct tpm2_session_header)),
        .pcrSession.handle = swap32(TPM_RS_PW),
    };

    hash_count = 0;
    p = cmd_rsp.extend_c.hashes;

    if ( sha1_digest != NULL ) {
        ++hash_count;
        PUT_16BIT(p, TPM_ALG_SHA1);
        PUT_BYTES(p, sha1_digest, SHA1_DIGEST_SIZE);
    }
    if ( sha256_digest != NULL ) {
        ++hash_count;
        PUT_16BIT(p, TPM_ALG_SHA256);
        PUT_BYTES(p, sha256_digest, SHA256_DIGEST_SIZE);
    }

    cmd_rsp.extend_c.hashCount = swap32(hash_count);

    /* Fill in command size (size of the whole buffer). */
    cmd_rsp.extend_c.h.paramSize = swap32(sizeof(cmd_rsp.extend_c) +
                                          (p - cmd_rsp.extend_c.hashes)),

    o_size = sizeof(cmd_rsp);
    send_cmd(loc, cmd_rsp.b, swap32(cmd_rsp.c.paramSize), &o_size);

    return swap32(cmd_rsp.r.returnCode);
}

static bool tpm20_has_sha1(unsigned loc)
{
    static int has_sha1 = -1;

    if ( has_sha1 < 0 ) {
        uint32_t rc;
        uint8_t test_sha1_digest[SHA1_DIGEST_SIZE] = {0};

        /* This is a valid way of checking hash support, using it to not
         * implement TPM2_GetCapability(). */
        rc = tpm20_pcr_extend(loc, /*pcr_handle=*/TPM_RH_NULL, test_sha1_digest,
                              /*sha256_digest=*/NULL);
        has_sha1 = (rc == 0);
    }

    return has_sha1 > 0;
}

static uint32_t tpm_hash_extend20(unsigned loc, uint8_t *buf, unsigned size,
                                  unsigned pcr, uint8_t *sha1_digest,
                                  uint8_t *sha256_digest)
{
    uint32_t rc;

    request_locality(loc);

    if ( tpm20_has_sha1(loc) )
        sha1_hash(buf, size, (uint32_t *)sha1_digest);
    else
        sha1_digest = NULL;

    sha256_hash(buf, size, (uint32_t *)sha256_digest);

    rc = tpm20_pcr_extend(loc, HR_PCR + pcr, sha1_digest, sha256_digest);

    relinquish_locality(loc);

    return rc;
}

#endif /* __EARLY_TPM__ */

/************************** end of TPM2.0 specific ****************************/

void tpm_hash_extend(unsigned loc, unsigned pcr, uint8_t *buf, unsigned size,
                     uint32_t type, uint8_t *log_data, unsigned log_data_size)
{
    void *evt_log_addr;
    uint32_t evt_log_size;

    find_evt_log(&evt_log_addr, &evt_log_size);

#ifndef __EARLY_TPM__
    /*
     * Low mappings are destroyed somewhere during the boot process, it includes
     * event log (marked as reserved by protect_txt_mem_regions().
     */
    map_pages_to_xen((unsigned long)evt_log_addr, maddr_to_mfn(__pa(evt_log_addr)),
                     PFN_UP(evt_log_size), __PAGE_HYPERVISOR_RW);
#endif

    if ( is_tpm12() ) {
        uint8_t sha1_digest[SHA1_DIGEST_SIZE];

        struct txt_ev_log_container_12 *evt_log = evt_log_addr;
        void *entry_digest = create_log_event12(evt_log, evt_log_size, pcr,
                                                type, log_data, log_data_size);

        /* We still need to write computed hash somewhere. */
        if ( entry_digest == NULL )
            entry_digest = sha1_digest;

        tpm_hash_extend12(loc, buf, size, pcr, entry_digest);
    } else {
        uint8_t sha1_digest[SHA1_DIGEST_SIZE];
        uint8_t sha256_digest[SHA256_DIGEST_SIZE];
        uint32_t rc;

        rc = tpm_hash_extend20(loc, buf, size, pcr, sha1_digest, sha256_digest);
        if ( rc != 0 ) {
#ifndef __EARLY_TPM__
            printk(XENLOG_ERR "Extending PCR%u failed with TPM error: 0x%08x\n",
                   pcr, rc);
#endif
        }
    }

#ifndef __EARLY_TPM__
    destroy_xen_mappings((unsigned long)evt_log_addr,
                         (unsigned long)evt_log_addr + PFN_UP(evt_log_size) * PAGE_SIZE);
#endif
}

#ifdef __EARLY_TPM__
void __stdcall tpm_extend_mbi(uint32_t *mbi)
{
    /* MBI starts with uint32_t total_size. */
    tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)mbi, *mbi,
                    TXT_EVTYPE_MBI, NULL, 0);
}
#endif
