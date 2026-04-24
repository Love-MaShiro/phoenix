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
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
    SPX_VLA(uint8_t, buf, SPX_N + SPX_SHA256_OUTPUT_BYTES + inblocks*SPX_N);
    uint8_t sha2_state[40];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + SPX_N,
                        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}

#ifdef SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
    SPX_VLA(uint8_t, buf, SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    uint8_t sha2_state[72];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_512(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha512_inc_finalize(outbuf, sha2_state, buf + SPX_N,
                        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
#endif

/**
 * Pre-computes the bitmask using MGF1.
 * In Robust variant, the mask is generated from (pub_seed || addr).
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
                        const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);

#ifdef SPX_SHA512
    /* Use MGF1-512 if we are in 512-bit mode (typically for 256-bit security) */
    if (inblocks > 1 || SPX_N >= 32) {
        mgf1_512(bitmask_out, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    } else 
#endif
    {
        mgf1_256(bitmask_out, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    }
}

/**
 * Completes the thash by XORing with a pre-computed bitmask and finalizing SHA2.
 * This is the optimized part intended for use inside the counter search loop.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
               const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
#ifdef SPX_SHA512
    if (inblocks > 1 || SPX_N >= 32) {
        unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
        /* Buffer for (addr || XORed_data) */
        SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
        uint8_t sha512_state[72];
        unsigned int i;

        /* 1. Copy address to buffer */
        memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);

        /* 2. XOR input with pre-computed bitmask and put into buffer */
        for (i = 0; i < inblocks * SPX_N; i++) {
            buf[SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
        }

        /* 3. Finalize using pre-computed state (pub_seed already absorbed) */
        memcpy(sha512_state, ctx->state_seeded_512, 72);
        sha512_inc_finalize(outbuf, sha512_state, buf,
                            SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
        memcpy(out, outbuf, SPX_N);
        return;
    }
#endif

    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    /* Buffer for (addr || XORed_data) */
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    uint8_t sha256_state[40];
    unsigned int i;

    /* 1. Copy address to buffer */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);

    /* 2. XOR input with pre-computed bitmask and put into buffer */
    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    /* 3. Finalize using pre-computed state (pub_seed already absorbed) */
    memcpy(sha256_state, ctx->state_seeded, 40);
    sha256_inc_finalize(outbuf, sha256_state, buf,
                        SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    memcpy(out, outbuf, SPX_N);
}

