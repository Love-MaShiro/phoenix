#include <stdint.h>
#include <string.h>

#include "fips202x4.h"
#include "params.h"
#include "thashx4.h"
#include "utils.h"

void thashx4(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3,
             unsigned int inblocks,
             const spx_ctx *ctx,
             uint32_t addrx4[4 * 8])
{
    SPX_VLA(uint8_t, buf0, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
    SPX_VLA(uint8_t, buf1, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
    SPX_VLA(uint8_t, buf2, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
    SPX_VLA(uint8_t, buf3, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);

    /* Match thash() exactly: pub_seed || addr || in. */
    memcpy(buf0, ctx->pub_seed, SPX_N);
    memcpy(buf1, ctx->pub_seed, SPX_N);
    memcpy(buf2, ctx->pub_seed, SPX_N);
    memcpy(buf3, ctx->pub_seed, SPX_N);

    memcpy(buf0 + SPX_N, addrx4 + 0 * 8, SPX_ADDR_BYTES);
    memcpy(buf1 + SPX_N, addrx4 + 1 * 8, SPX_ADDR_BYTES);
    memcpy(buf2 + SPX_N, addrx4 + 2 * 8, SPX_ADDR_BYTES);
    memcpy(buf3 + SPX_N, addrx4 + 3 * 8, SPX_ADDR_BYTES);

    memcpy(buf0 + SPX_N + SPX_ADDR_BYTES, in0, inblocks * SPX_N);
    memcpy(buf1 + SPX_N + SPX_ADDR_BYTES, in1, inblocks * SPX_N);
    memcpy(buf2 + SPX_N + SPX_ADDR_BYTES, in2, inblocks * SPX_N);
    memcpy(buf3 + SPX_N + SPX_ADDR_BYTES, in3, inblocks * SPX_N);

    shake256x4(out0, out1, out2, out3, SPX_N,
               buf0, buf1, buf2, buf3,
               SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
}
