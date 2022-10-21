/*
 * Copyright (c) 2022-2024 3mdeb Sp. z o.o. All rights reserved.
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

#include <xen/sha1.h>
#include <xen/types.h>
#include <asm/intel_txt.h>
#include <asm/tpm.h>

#ifdef __EARLY_TPM__
/*
 * This entry point is entered from xen/arch/x86/boot/head.S with MBI base at
 * %eax.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  tpm_extend_mbi           \n"
    );

#ifdef __va
#error "__va defined in non-paged mode!"
#endif

#define __va(x)     _p(x)

/*
 * The code is being compiled as a standalone binary without linking to any
 * other part of Xen.  Providing implementation of builtin functions in this
 * case is necessary if compiler chooses to not use an inline builtin.
 */
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

#endif  /* __EARLY_TPM__ */

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

/****************************** TPM1.2 specific *******************************/
#define TPM_ORD_Extend              0x00000014
#define TPM_ORD_SHA1Start           0x000000A0
#define TPM_ORD_SHA1Update          0x000000A1
#define TPM_ORD_SHA1CompleteExtend  0x000000A3

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RSP_COMMAND         0x00C4

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
static bool tpm12_hash_extend(unsigned loc, uint8_t *buf, unsigned size,
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
static bool tpm12_hash_extend(unsigned loc, uint8_t *buf, unsigned size,
                              unsigned pcr, uint8_t *out_digest)
{
    union cmd_rsp cmd_rsp;
    unsigned o_size = sizeof(cmd_rsp);

    sha1_hash(buf, size, out_digest);

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

void tpm_hash_extend(unsigned loc, unsigned pcr, uint8_t *buf, unsigned size,
                     uint32_t type, uint8_t *log_data, unsigned log_data_size)
{
    void *evt_log_addr;
    uint32_t evt_log_size;

    struct slr_table *slrt = __va(txt_find_slrt());

    find_evt_log(slrt, &evt_log_addr, &evt_log_size);
    evt_log_addr = __va((uintptr_t)evt_log_addr);

    if ( is_tpm12() ) {
        uint8_t sha1_digest[SHA1_DIGEST_SIZE];

        struct txt_ev_log_container_12 *evt_log = evt_log_addr;
        void *entry_digest = create_log_event12(evt_log, evt_log_size, pcr,
                                                type, log_data, log_data_size);

        /* We still need to write computed hash somewhere. */
        if ( entry_digest == NULL )
            entry_digest = sha1_digest;

        if ( !tpm12_hash_extend(loc, buf, size, pcr, entry_digest) ) {
#ifndef __EARLY_TPM__
            printk(XENLOG_ERR "Extending PCR%u failed\n", pcr);
#endif
        }
    }
}

#ifdef __EARLY_TPM__
void tpm_extend_mbi(uint32_t *mbi)
{
    /* MBI starts with uint32_t total_size. */
    tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)mbi, *mbi,
                    TXT_EVTYPE_SLAUNCH, NULL, 0);
}
#endif
