/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 *
 * This header is for TPM2.0-related definitions defined by Trusted Computing
 * Group (TCG).
 */

#ifndef X86_TPM2_H
#define X86_TPM2_H

#include <xen/inttypes.h>

#include <asm/tpm.h>

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

/* All fields of the following structs are big endian. */

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

/* The structures below are for TPM event log and these are in little-endian. */

struct tpm2_pcr_event_header {
    uint32_t pcrIndex;
    uint32_t eventType;
    uint32_t digestCount;
    uint8_t digests[0];
    /*
     * Each hash is represented as:
     * struct {
     *     uint16_t hashAlg;
     *     uint8_t hash[size of hashAlg];
     * };
     */
    /* uint32_t eventSize; */
    /* uint8_t event[0]; */
} __packed;

struct tpm2_digest_sizes {
    uint16_t algId;
    uint16_t digestSize;
} __packed;

struct tpm2_spec_id_event {
    uint32_t pcrIndex;
    uint32_t eventType;
    uint8_t digest[20];
    uint32_t eventSize;
    uint8_t signature[16];
    uint32_t platformClass;
    uint8_t specVersionMinor;
    uint8_t specVersionMajor;
    uint8_t specErrata;
    uint8_t uintnSize;
    uint32_t digestCount;
    struct tpm2_digest_sizes digestSizes[0]; /* variable number of members */
    /* uint8_t vendorInfoSize; */
    /* uint8_t vendorInfo[vendorInfoSize]; */
} __packed;

#endif /* X86_TPM2_H */
