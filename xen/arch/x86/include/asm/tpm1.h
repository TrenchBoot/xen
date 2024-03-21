/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 *
 * This header is for TPM1.2-related definitions defined by Trusted Computing
 * Group (TCG).
 */

#ifndef X86_TPM1_H
#define X86_TPM1_H

#include <xen/inttypes.h>
#include <xen/sha1.h>

#include <asm/tpm.h>

#define TPM_ORD_Extend              0x00000014
#define TPM_ORD_SHA1Start           0x000000A0
#define TPM_ORD_SHA1Update          0x000000A1
#define TPM_ORD_SHA1CompleteExtend  0x000000A3

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RSP_COMMAND         0x00C4

/* All fields of the following structs are big endian. */

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

/* The structures below are for TPM event log and these are in little-endian. */

struct TPM12_PCREvent {
    uint32_t PCRIndex;
    uint32_t Type;
    uint8_t Digest[SHA1_DIGEST_SIZE];
    uint32_t Size;
    uint8_t Data[];
};

struct tpm1_spec_id_event {
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
    uint8_t vendorInfoSize;
    uint8_t vendorInfo[0];  /* variable number of members */
} __packed;

#endif /* X86_TPM1_H */
