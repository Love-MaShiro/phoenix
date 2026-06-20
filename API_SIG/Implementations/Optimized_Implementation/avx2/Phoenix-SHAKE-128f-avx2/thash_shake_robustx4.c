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
    SPX_VLA(uint8_t, bitmask0, inblocks * SPX_N);
    SPX_VLA(uint8_t, bitmask1, inblocks * SPX_N);
    SPX_VLA(uint8_t, bitmask2, inblocks * SPX_N);
    SPX_VLA(uint8_t, bitmask3, inblocks * SPX_N);
    unsigned int i;

    /* Match robust thash(): bitmask = shake256(pub_seed || addr). */
    memcpy(buf0, ctx->pub_seed, SPX_N);
    memcpy(buf1, ctx->pub_seed, SPX_N);
    memcpy(buf2, ctx->pub_seed, SPX_N);
    memcpy(buf3, ctx->pub_seed, SPX_N);

    memcpy(buf0 + SPX_N, addrx4 + 0 * 8, SPX_ADDR_BYTES);
    memcpy(buf1 + SPX_N, addrx4 + 1 * 8, SPX_ADDR_BYTES);
    memcpy(buf2 + SPX_N, addrx4 + 2 * 8, SPX_ADDR_BYTES);
    memcpy(buf3 + SPX_N, addrx4 + 3 * 8, SPX_ADDR_BYTES);

    shake256x4(bitmask0, bitmask1, bitmask2, bitmask3, inblocks * SPX_N,
               buf0, buf1, buf2, buf3, SPX_N + SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf0[SPX_N + SPX_ADDR_BYTES + i] = in0[i] ^ bitmask0[i];
        buf1[SPX_N + SPX_ADDR_BYTES + i] = in1[i] ^ bitmask1[i];
        buf2[SPX_N + SPX_ADDR_BYTES + i] = in2[i] ^ bitmask2[i];
        buf3[SPX_N + SPX_ADDR_BYTES + i] = in3[i] ^ bitmask3[i];
    }

    shake256x4(out0, out1, out2, out3, SPX_N,
               buf0, buf1, buf2, buf3,
               SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
}
