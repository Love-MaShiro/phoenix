#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"

#include "haraka.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
    /* Use dynamic allocation to support larger SPX_N values */
    unsigned char *outbuf = malloc(SPX_N);
    unsigned char *buf_tmp = malloc(SPX_ADDR_BYTES + SPX_N);
    if (!outbuf || !buf_tmp) {
        if (outbuf) free(outbuf);
        if (buf_tmp) free(buf_tmp);
        return;
    }

    if (inblocks == 1) {
        /* F function */
        /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
        memset(buf_tmp, 0, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp, addr, SPX_ADDR_BYTES);
        memcpy(buf_tmp + SPX_ADDR_BYTES, in, SPX_N);

        haraka512(outbuf, buf_tmp, ctx);
        memcpy(out, outbuf, SPX_N);
    } else {
        /* All other tweakable hashes*/
        memcpy(buf, addr, SPX_ADDR_BYTES);
        memcpy(buf + SPX_ADDR_BYTES, in, inblocks * SPX_N);

        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N, ctx);
    }
    
    free(outbuf);
    free(buf_tmp);
}

void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    (void) bitmask_out;
    (void) inblocks;
    (void) ctx;
    (void) addr;
}

void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    (void) bitmask;
    thash(out, in, inblocks, ctx, addr);
}
