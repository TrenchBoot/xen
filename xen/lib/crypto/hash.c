/*
 * hash.c: support functions for hash_t type
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <xen/lib.h>
#include <xen/lib/sha1.h>
#include <xen/lib/sha2.h>
#include <xen/lib/hash.h>

/*
 * are_hashes_equal
 *
 * compare whether two hash values are equal.
 *
 */
bool are_hashes_equal(
    const hash_t *hash1, const hash_t *hash2, uint16_t hash_alg)
{
    unsigned int len;

    if ( ( hash1 == NULL ) || ( hash2 == NULL ) )
    {
        printk(XENLOG_ERR"Error: hash pointer is zero.\n");
        return false;
    }

    len = get_hash_size(hash_alg);
    if ( len > 0 )
        return (memcmp(hash1, hash2, len) == 0);
    else
    {
        printk(XENLOG_ERR"unsupported hash alg (%u)\n", hash_alg);
        return false;
    }
}

/*
 * hash_buffer
 *
 * hash the buffer according to the algorithm
 *
 */
bool hash_buffer(
    const unsigned char* buf, size_t size, hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL )
    {
        printk(XENLOG_ERR"Error: There is no space for output hash.\n");
        return false;
    }

    if ( hash_alg == HASH_ALG_SHA1 )
    {
        sha1_buffer(buf, size, hash->sha1);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA256 )
    {
        sha256_buffer(buf, size, hash->sha256);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA384 )
    {
        sha384_buffer(buf, size, hash->sha384);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA512 )
    {
        sha512_buffer(buf, size, hash->sha512);
        return true;
    }
    else
    {
        printk(XENLOG_ERR"unsupported hash alg (%u)\n", hash_alg);
        return false;
    }
}

/*
 * extend_hash
 *
 * perform "extend" of two hashes (i.e. hash1 = SHA(hash1 || hash2)
 *
 */
bool extend_hash(hash_t *hash1, const hash_t *hash2, uint16_t hash_alg)
{
    uint8_t buf[2*HASH_MAX_LENGTH];

    if ( hash1 == NULL || hash2 == NULL )
    {
        if ( hash1 == NULL )
            printk(XENLOG_ERR"Error: There is no space for output hash.\n");
        if ( hash2 == NULL )
            printk(XENLOG_ERR"Error: Must provide two hashes.\n");
        return false;
    }

    if ( hash_alg == HASH_ALG_SHA1 )
    {
        memcpy(buf, &(hash1->sha1), sizeof(hash1->sha1));
        memcpy(buf + sizeof(hash1->sha1), &(hash2->sha1), sizeof(hash1->sha1));
        sha1_buffer(buf, 2*sizeof(hash1->sha1), hash1->sha1);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA256 )
    {
        memcpy(buf, &(hash1->sha256), sizeof(hash1->sha256));
        memcpy(buf + sizeof(hash1->sha256), &(hash2->sha256),
            sizeof(hash1->sha256));
        sha256_buffer(buf, 2*sizeof(hash1->sha256), hash1->sha256);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA384 )
    {
        memcpy(buf, &(hash1->sha384), sizeof(hash1->sha384));
        memcpy(buf + sizeof(hash1->sha384), &(hash2->sha384),
            sizeof(hash1->sha384));
        sha384_buffer(buf, 2*sizeof(hash1->sha384), hash1->sha384);
        return true;
    }
    else if ( hash_alg == HASH_ALG_SHA512 )
    {
        memcpy(buf, &(hash1->sha512), sizeof(hash1->sha512));
        memcpy(buf + sizeof(hash1->sha512), &(hash2->sha512),
                sizeof(hash1->sha512));
        sha512_buffer(buf, 2*sizeof(hash1->sha512), hash1->sha512);
        return true;
    }
    else
    {
        printk(XENLOG_ERR"unsupported hash alg (%u)\n", hash_alg);
        return false;
    }
}

void print_hash(const hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL )
    {
        printk(XENLOG_WARNING"NULL");
        return;
    }

    if ( hash_alg == HASH_ALG_SHA1 )
        printk(XENLOG_INFO"%*ph\n", get_hash_size(HASH_ALG_SHA1),
            (uint8_t *)hash->sha1);
    else if ( hash_alg == HASH_ALG_SHA256 )
        printk(XENLOG_INFO"%*ph\n", get_hash_size(HASH_ALG_SHA256),
            (uint8_t *)hash->sha256);
    else if ( hash_alg == HASH_ALG_SHA384 )
        printk(XENLOG_INFO"%*ph\n", get_hash_size(HASH_ALG_SHA384),
            (uint8_t *)hash->sha384);
    else
        printk(XENLOG_WARNING"unsupported hash alg (%u)\n", hash_alg);
}

void copy_hash(hash_t *dest_hash, const hash_t *src_hash, uint16_t hash_alg)
{
    unsigned int len;

    if ( dest_hash == NULL || src_hash == NULL )
    {
        printk(XENLOG_WARNING"hashes are NULL\n");
        return;
    }

    len = get_hash_size(hash_alg);
    if ( len > 0 )
        memcpy(dest_hash, src_hash, len);
    else
        printk(XENLOG_WARNING"unsupported hash alg (%u)\n", hash_alg);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
