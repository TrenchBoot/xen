/*
 * hash.h:  definition of and support fns for hash_t type
 *
 * Copyright (c) 2006-2007, Intel Corporation
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

#ifndef __HASH_H__
#define __HASH_H__

#define HASH_ALG_SHA1_LG 0x0000  /* legacy define for SHA1 */
#define HASH_ALG_SHA1    0x0004
#define HASH_ALG_SHA256  0x000B
#define HASH_ALG_SM3     0x0012 /* Unsupported */
#define HASH_ALG_SHA384  0x000C
#define HASH_ALG_SHA512  0x000D
#define HASH_ALG_NULL    0x0010

#define SHA1_LENGTH        20
#define SHA256_LENGTH      32
#define SHA384_LENGTH      48
#define SHA512_LENGTH      64

#define HASH_MAX_LENGTH     SHA512_LENGTH

typedef uint8_t sha1_hash_t[SHA1_LENGTH];
typedef uint8_t sha256_hash_t[SHA256_LENGTH];
typedef uint8_t sha384_hash_t[SHA384_LENGTH];
typedef uint8_t sha512_hash_t[SHA512_LENGTH];

typedef union {
    uint8_t    sha1[SHA1_LENGTH];
    uint8_t    sha256[SHA256_LENGTH];
    uint8_t    sha384[SHA384_LENGTH];
    uint8_t    sha512[SHA512_LENGTH];
} hash_t;

static inline const char *hash_alg_to_string(uint16_t hash_alg)
{
    if ( hash_alg == HASH_ALG_SHA1 || hash_alg == HASH_ALG_SHA1_LG )
        return "HASH_ALG_SHA1";
    else if ( hash_alg == HASH_ALG_SHA256 )
        return "HASH_ALG_SHA256";
    else if ( hash_alg == HASH_ALG_SM3 )
        return "HASH_ALG_SM3";
    else if ( hash_alg == HASH_ALG_SHA384 )
        return "HASH_ALG_SHA384";
    else if ( hash_alg == HASH_ALG_SHA512 )
        return "HASH_ALG_SHA512";
    else
        return "unsupported";
}

static inline unsigned int get_hash_size(uint16_t hash_alg)
{
    if ( hash_alg == HASH_ALG_SHA1 || hash_alg == HASH_ALG_SHA1_LG )
        return SHA1_LENGTH;
    else if ( hash_alg == HASH_ALG_SHA256 )
        return SHA256_LENGTH;
    else if ( hash_alg == HASH_ALG_SHA384 )
        return SHA384_LENGTH;
    else if ( hash_alg == HASH_ALG_SHA512 )
        return SHA512_LENGTH;
    else
        return 0;
}


bool are_hashes_equal(
    const hash_t *hash1, const hash_t *hash2, uint16_t hash_alg);
bool hash_buffer(
    const unsigned char* buf, size_t size, hash_t *hash, uint16_t hash_alg);
bool extend_hash(
    hash_t *hash1, const hash_t *hash2, uint16_t hash_alg);
void print_hash(const hash_t *hash, uint16_t hash_alg);
bool import_hash(const char *string, hash_t *hash, uint16_t alg);
void copy_hash(
    hash_t *dest_hash, const hash_t *src_hash, uint16_t hash_alg);


#endif    /* __HASH_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
