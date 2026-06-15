#include <stdint.h>
#include <string.h>

#include "address.h"
#include "fips202x4.h"
#include "hashx4.h"
#include "params.h"

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const spx_ctx *ctx,
                const uint32_t addrx4[4 * 8])
{
    unsigned char buf0[2 * SPX_N + SPX_ADDR_BYTES];
    unsigned char buf1[2 * SPX_N + SPX_ADDR_BYTES];
    unsigned char buf2[2 * SPX_N + SPX_ADDR_BYTES];
    unsigned char buf3[2 * SPX_N + SPX_ADDR_BYTES];

    /* Match prf_addr() exactly: pub_seed || addr || sk_seed. */
    memcpy(buf0, ctx->pub_seed, SPX_N);
    memcpy(buf1, ctx->pub_seed, SPX_N);
    memcpy(buf2, ctx->pub_seed, SPX_N);
    memcpy(buf3, ctx->pub_seed, SPX_N);

    memcpy(buf0 + SPX_N, addrx4 + 0 * 8, SPX_ADDR_BYTES);
    memcpy(buf1 + SPX_N, addrx4 + 1 * 8, SPX_ADDR_BYTES);
    memcpy(buf2 + SPX_N, addrx4 + 2 * 8, SPX_ADDR_BYTES);
    memcpy(buf3 + SPX_N, addrx4 + 3 * 8, SPX_ADDR_BYTES);

    memcpy(buf0 + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf1 + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf2 + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);
    memcpy(buf3 + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    shake256x4(out0, out1, out2, out3, SPX_N,
               buf0, buf1, buf2, buf3, 2 * SPX_N + SPX_ADDR_BYTES);
}
