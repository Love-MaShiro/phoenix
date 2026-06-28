#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "hash.h"
#include "hash_sm3.h"
#include "hashx4.h"
#include "utils.h"

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const spx_ctx *ctx,
                const uint32_t addrx4[4 * 8])
{
    SPX_VLA(uint8_t, buf0, SPX_SM3_ADDR_BYTES + SPX_N);
    SPX_VLA(uint8_t, buf1, SPX_SM3_ADDR_BYTES + SPX_N);
    SPX_VLA(uint8_t, buf2, SPX_SM3_ADDR_BYTES + SPX_N);
    SPX_VLA(uint8_t, buf3, SPX_SM3_ADDR_BYTES + SPX_N);

    memcpy(buf0, addrx4 + 0 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf1, addrx4 + 1 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf2, addrx4 + 2 * 8, SPX_SM3_ADDR_BYTES);
    memcpy(buf3, addrx4 + 3 * 8, SPX_SM3_ADDR_BYTES);

    memcpy(buf0 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf1 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf2 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf3 + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);

    /* Use sm3_xof for correct XOF output length (SPX_N = 16 bytes) */
    sm3_xof(out0, SPX_N, buf0, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_xof(out1, SPX_N, buf1, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_xof(out2, SPX_N, buf2, SPX_SM3_ADDR_BYTES + SPX_N);
    sm3_xof(out3, SPX_N, buf3, SPX_SM3_ADDR_BYTES + SPX_N);
}