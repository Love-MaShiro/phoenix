#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "hash_sm3.h"
#include "hash_sm3x4.h"
#include "params.h"
#include "sm3_internal.h"
#include "utils.h"

static void sm3_xofx4_scalar(unsigned char *out0, unsigned char *out1,
                             unsigned char *out2, unsigned char *out3,
                             unsigned long outlen,
                             const unsigned char *in0,
                             const unsigned char *in1,
                             const unsigned char *in2,
                             const unsigned char *in3,
                             unsigned long inlen)
{
    sm3_xof(out0, outlen, in0, inlen);
    sm3_xof(out1, outlen, in1, inlen);
    sm3_xof(out2, outlen, in2, inlen);
    sm3_xof(out3, outlen, in3, inlen);
}

static void store_be32(unsigned char out[4], uint32_t x)
{
    out[0] = (unsigned char)(x >> 24);
    out[1] = (unsigned char)(x >> 16);
    out[2] = (unsigned char)(x >> 8);
    out[3] = (unsigned char)x;
}

void sm3_xofx4(unsigned char *out0, unsigned char *out1,
               unsigned char *out2, unsigned char *out3,
               unsigned long outlen,
               const unsigned char *in0, const unsigned char *in1,
               const unsigned char *in2, const unsigned char *in3,
               unsigned long inlen)
{
    if (outlen == 0) {
        return;
    }

#if defined(AVX2_OPTIMIZED)
    size_t msg_len = (size_t)inlen + 4;
    unsigned char *buf0 = (unsigned char *)malloc(msg_len);
    unsigned char *buf1 = (unsigned char *)malloc(msg_len);
    unsigned char *buf2 = (unsigned char *)malloc(msg_len);
    unsigned char *buf3 = (unsigned char *)malloc(msg_len);
    unsigned char block0[SPX_SM3_OUTPUT_BYTES], block1[SPX_SM3_OUTPUT_BYTES];
    unsigned char block2[SPX_SM3_OUTPUT_BYTES], block3[SPX_SM3_OUTPUT_BYTES];
    unsigned char tmp4[SPX_SM3_OUTPUT_BYTES], tmp5[SPX_SM3_OUTPUT_BYTES];
    unsigned char tmp6[SPX_SM3_OUTPUT_BYTES], tmp7[SPX_SM3_OUTPUT_BYTES];
    unsigned long produced = 0;
    uint32_t ct = 1;

    if (buf0 == NULL || buf1 == NULL || buf2 == NULL || buf3 == NULL) {
        free(buf0);
        free(buf1);
        free(buf2);
        free(buf3);
        sm3_xofx4_scalar(out0, out1, out2, out3, outlen,
                         in0, in1, in2, in3, inlen);
        return;
    }

    memcpy(buf0, in0, inlen);
    memcpy(buf1, in1, inlen);
    memcpy(buf2, in2, inlen);
    memcpy(buf3, in3, inlen);

    while (produced < outlen) {
        unsigned long take = outlen - produced;
        if (take > SPX_SM3_OUTPUT_BYTES) {
            take = SPX_SM3_OUTPUT_BYTES;
        }

        store_be32(buf0 + inlen, ct);
        store_be32(buf1 + inlen, ct);
        store_be32(buf2 + inlen, ct);
        store_be32(buf3 + inlen, ct);

        sm3x8_avx2(block0, block1, block2, block3,
                   tmp4, tmp5, tmp6, tmp7,
                   buf0, buf1, buf2, buf3,
                   buf0, buf1, buf2, buf3,
                   msg_len);

        memcpy(out0 + produced, block0, take);
        memcpy(out1 + produced, block1, take);
        memcpy(out2 + produced, block2, take);
        memcpy(out3 + produced, block3, take);
        produced += take;
        ct++;
    }

    free(buf0);
    free(buf1);
    free(buf2);
    free(buf3);
#else
    sm3_xofx4_scalar(out0, out1, out2, out3, outlen,
                     in0, in1, in2, in3, inlen);
#endif
}

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const spx_ctx *ctx,
                const uint32_t addrx4[4 * 8])
{
    /* Use sm3_inc_finalize (standard incremental SM3) to match
       the scalar prf_addr in hash_sm3.c. Each lane independently
       hashes ADDR‖SK.seed using the precomputed pub_seed state. */
    uint8_t sm3_state0[40], sm3_state1[40], sm3_state2[40], sm3_state3[40];
    unsigned char buf0[SPX_SM3_ADDR_BYTES + SPX_N];
    unsigned char buf1[SPX_SM3_ADDR_BYTES + SPX_N];
    unsigned char buf2[SPX_SM3_ADDR_BYTES + SPX_N];
    unsigned char buf3[SPX_SM3_ADDR_BYTES + SPX_N];
    unsigned char outbuf0[SPX_SM3_OUTPUT_BYTES];
    unsigned char outbuf1[SPX_SM3_OUTPUT_BYTES];
    unsigned char outbuf2[SPX_SM3_OUTPUT_BYTES];
    unsigned char outbuf3[SPX_SM3_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sm3_state0, ctx->state_seeded_sm3, 40);
    memcpy(sm3_state1, ctx->state_seeded_sm3, 40);
    memcpy(sm3_state2, ctx->state_seeded_sm3, 40);
    memcpy(sm3_state3, ctx->state_seeded_sm3, 40);

    /* Remainder: ADDR^c ‖ SK.seed */
    memcpy(buf0, addrx4 + 0 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf1, addrx4 + 1 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf2, addrx4 + 2 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf3, addrx4 + 3 * 8, SPX_SM3_ADDR_BYTES);

    memcpy(buf0 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf1 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf2 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf3 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sm3_inc_finalize(outbuf0, sm3_state0, buf0, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_inc_finalize(outbuf1, sm3_state1, buf1, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_inc_finalize(outbuf2, sm3_state2, buf2, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_inc_finalize(outbuf3, sm3_state3, buf3, SPX_SM3_ADDR_BYTES + SPX_N);

    memcpy(out0, outbuf0, SPX_N);
    memcpy(out1, outbuf1, SPX_N);
    memcpy(out2, outbuf2, SPX_N);
    memcpy(out3, outbuf3, SPX_N);
}
