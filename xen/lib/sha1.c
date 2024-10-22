/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SHA1 routine optimized to do word accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 *
 * This was based on the git SHA1 implementation.
 */

#include <xen/bitops.h>
#include <xen/types.h>
#include <xen/sha1.h>
#include <xen/unaligned.h>

/*
 * If you have 32 registers or more, the compiler can (and should)
 * try to change the array[] accesses into registers. However, on
 * machines with less than ~25 registers, that won't really work,
 * and at least gcc will make an unholy mess of it.
 *
 * So to avoid that mess which just slows things down, we force
 * the stores to memory to actually happen (we might be better off
 * with a 'W(t)=(val);asm("":"+m" (W(t))' there instead, as
 * suggested by Artur Skawina - that will also make gcc unable to
 * try to do the silly "optimize away loads" part because it won't
 * see what the value will be).
 *
 * Ben Herrenschmidt reports that on PPC, the C version comes close
 * to the optimized asm with this (ie on PPC you don't want that
 * 'volatile', since there are lots of registers).
 *
 * On ARM we get the best code generation by forcing a full memory barrier
 * between each SHA_ROUND, otherwise gcc happily get wild with spilling and
 * the stack frame size simply explode and performance goes down the drain.
 */

#ifdef CONFIG_X86
  #define setW(x, val) (*(volatile __u32 *)&W(x) = (val))
#elif defined(CONFIG_ARM)
  #define setW(x, val) do { W(x) = (val); __asm__("":::"memory"); } while ( 0 )
#else
  #define setW(x, val) (W(x) = (val))
#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x) & 15])

/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) get_unaligned_be32((__u32 *)data + t)
#define SHA_MIX(t) rol32(W(t + 13) ^ W(t + 8) ^ W(t + 2) ^ W(t), 1)

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) do { \
        __u32 TEMP = input(t); setW(t, TEMP);                 \
        E += TEMP + rol32(A, 5) + (fn) + (constant);          \
        B = ror32(B, 2);                                      \
        TEMP = E; E = D; D = C; C = B; B = A; A = TEMP;       \
    } while ( 0 )

#define T_0_15(t, A, B, C, D, E)  \
        SHA_ROUND(t, SHA_SRC, (((C ^ D) & B) ^ D), 0x5a827999, A, B, C, D, E)
#define T_16_19(t, A, B, C, D, E) \
        SHA_ROUND(t, SHA_MIX, (((C ^ D) & B) ^ D), 0x5a827999, A, B, C, D, E)
#define T_20_39(t, A, B, C, D, E) \
        SHA_ROUND(t, SHA_MIX, (B ^ C ^ D), 0x6ed9eba1, A, B, C, D, E)
#define T_40_59(t, A, B, C, D, E)                                             \
        SHA_ROUND(t, SHA_MIX, ((B & C) + (D & (B ^ C))), 0x8f1bbcdc, A, B, C, \
                  D, E)
#define T_60_79(t, A, B, C, D, E) \
        SHA_ROUND(t, SHA_MIX, (B ^ C ^ D), 0xca62c1d6, A, B, C, D, E)

#define SHA1_BLOCK_SIZE         64
#define SHA1_WORKSPACE_WORDS    16

struct sha1_state {
    u32 state[SHA1_DIGEST_SIZE / 4];
    u64 count;
    u8 buffer[SHA1_BLOCK_SIZE];
};

typedef void sha1_block_fn(struct sha1_state *sst, const u8 *src, int blocks);

/**
 * sha1_transform - single block SHA1 transform (deprecated)
 *
 * @digest: 160 bit digest to update
 * @data:   512 bits of data to hash
 * @array:  16 words of workspace (see note)
 *
 * This function executes SHA-1's internal compression function.  It updates the
 * 160-bit internal state (@digest) with a single 512-bit data block (@data).
 *
 * Don't use this function.  SHA-1 is no longer considered secure.  And even if
 * you do have to use SHA-1, this isn't the correct way to hash something with
 * SHA-1 as this doesn't handle padding and finalization.
 *
 * Note: If the hash is security sensitive, the caller should be sure
 * to clear the workspace. This is left to the caller to avoid
 * unnecessary clears between chained hashing operations.
 */
void sha1_transform(__u32 *digest, const u8 *data, __u32 *array)
{
    __u32 A, B, C, D, E;
    unsigned int i = 0;

    A = digest[0];
    B = digest[1];
    C = digest[2];
    D = digest[3];
    E = digest[4];

    /* Round 1 - iterations 0-16 take their input from 'data' */
    for ( ; i < 16; ++i )
        T_0_15(i, A, B, C, D, E);

    /* Round 1 - tail. Input from 512-bit mixing array */
    for ( ; i < 20; ++i )
        T_16_19(i, A, B, C, D, E);

    /* Round 2 */
    for ( ; i < 40; ++i )
        T_20_39(i, A, B, C, D, E);

    /* Round 3 */
    for ( ; i < 60; ++i )
        T_40_59(i, A, B, C, D, E);

    /* Round 4 */
    for ( ; i < 80; ++i )
        T_60_79(i, A, B, C, D, E);

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
}

static void sha1_init(struct sha1_state *sctx)
{
    sctx->state[0] = 0x67452301UL;
    sctx->state[1] = 0xefcdab89UL;
    sctx->state[2] = 0x98badcfeUL;
    sctx->state[3] = 0x10325476UL;
    sctx->state[4] = 0xc3d2e1f0UL;
    sctx->count = 0;
}

static void sha1_do_update(struct sha1_state *sctx,
                           const u8 *data,
                           unsigned int len,
                           sha1_block_fn *block_fn)
{
    unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

    sctx->count += len;

    if ( unlikely((partial + len) >= SHA1_BLOCK_SIZE) )
    {
        int blocks;

        if ( partial )
        {
            int p = SHA1_BLOCK_SIZE - partial;

            memcpy(sctx->buffer + partial, data, p);
            data += p;
            len -= p;

            block_fn(sctx, sctx->buffer, 1);
        }

        blocks = len / SHA1_BLOCK_SIZE;
        len %= SHA1_BLOCK_SIZE;

        if ( blocks )
        {
            block_fn(sctx, data, blocks);
            data += blocks * SHA1_BLOCK_SIZE;
        }
        partial = 0;
    }
    if ( len )
        memcpy(sctx->buffer + partial, data, len);
}

static void sha1_do_finalize(struct sha1_state *sctx, sha1_block_fn *block_fn)
{
    const int bit_offset = SHA1_BLOCK_SIZE - sizeof(__be64);
    __be64 *bits = (__be64 *)(sctx->buffer + bit_offset);
    unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

    sctx->buffer[partial++] = 0x80;
    if ( partial > bit_offset )
    {
        memset(sctx->buffer + partial, 0x0, SHA1_BLOCK_SIZE - partial);
        partial = 0;

        block_fn(sctx, sctx->buffer, 1);
    }

    memset(sctx->buffer + partial, 0x0, bit_offset - partial);
    *bits = cpu_to_be64(sctx->count << 3);
    block_fn(sctx, sctx->buffer, 1);
}

static void sha1_finish(struct sha1_state *sctx, u8 *out)
{
    __be32 *digest = (__be32 *)out;
    int i;

    for ( i = 0; i < SHA1_DIGEST_SIZE / sizeof(__be32); i++ )
        put_unaligned_be32(sctx->state[i], digest++);

    memset(sctx, 0, sizeof(*sctx));
}

static void sha1_generic_block_fn(struct sha1_state *sctx, const u8 *src,
                                  int blocks)
{
    u32 temp[SHA1_WORKSPACE_WORDS];

    while ( blocks-- )
    {
        sha1_transform(sctx->state, src, temp);
        src += SHA1_BLOCK_SIZE;
    }
    memset(temp, 0, sizeof(temp));
}

void sha1_hash(const u8 *data, unsigned int len, u8 *out)
{
    struct sha1_state sctx;

    sha1_init(&sctx);
    sha1_do_update(&sctx, data, len, sha1_generic_block_fn);
    sha1_do_finalize(&sctx, sha1_generic_block_fn);
    sha1_finish(&sctx, out);
}
