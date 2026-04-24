#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sha2.h"

#ifdef SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    
#ifdef SPX_SHA512
    if (inblocks > 1 || SPX_N > 32) {
	thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif

    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}

#ifdef SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    uint8_t sha2_state[72];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha512_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
#endif

/**
 * Pre-computes the bitmask using MGF1.
 * This should be called OUTSIDE the counter search loop.
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
                        const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES];

    /* MGF1 seed consists of pub_seed and the address */
    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);

    /* Generate the mask */
#ifdef SPX_SHA512
    if (inblocks > 1 || SPX_N >= 32) {
        mgf1_512(bitmask_out, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    } else 
#endif
    {
        mgf1_256(bitmask_out, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    }
}

/**
 * Completes the thash by XORing with a pre-computed bitmask.
 * This is called INSIDE the counter search loop.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
               const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    unsigned char buf[SPX_SHA256_ADDR_BYTES + inblocks * SPX_N];
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES]; // Large enough for both 256 and 512
    unsigned int i;

    /* 1. Copy the address into the buffer */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);

    /* 2. XOR the input with the pre-computed bitmask */
    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    /* 3. Finalize the hash using the pre-computed state (which already absorbed pub_seed) */
#ifdef SPX_SHA512
    if (inblocks > 1 || SPX_N >= 32) {
        uint8_t sha512_state[72];
        memcpy(sha512_state, ctx->state_seeded_512, 72);
        sha512_inc_finalize(outbuf, sha512_state, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    } else 
#endif
    {
        uint8_t sha256_state[40];
        memcpy(sha256_state, ctx->state_seeded, 40);
        sha256_inc_finalize(outbuf, sha256_state, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    }

    memcpy(out, outbuf, SPX_N);
}



