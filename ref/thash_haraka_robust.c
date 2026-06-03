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
    SPX_VLA(uint8_t, bitmask, inblocks*SPX_N);
    /* Use dynamic allocation to support larger SPX_N values */
    unsigned char *outbuf = malloc(SPX_N);
    unsigned char *buf_tmp = malloc(SPX_ADDR_BYTES + SPX_N);
    unsigned int i;
    
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

        haraka256(outbuf, buf_tmp, ctx);
        for (i = 0; i < inblocks * SPX_N; i++) {
            buf_tmp[SPX_ADDR_BYTES + i] = in[i] ^ outbuf[i];
        }
        haraka512(outbuf, buf_tmp, ctx);
        memcpy(out, outbuf, SPX_N);
    } else {
        /* All other tweakable hashes*/
        memcpy(buf, addr, SPX_ADDR_BYTES);
        haraka_S(bitmask, inblocks * SPX_N, buf, SPX_ADDR_BYTES, ctx);

        for (i = 0; i < inblocks * SPX_N; i++) {
            buf[SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
        }

        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N, ctx);
    }
    
    free(outbuf);
    free(buf_tmp);
}

void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    if (inblocks == 1) {
        /* Use dynamic allocation to support larger SPX_N values */
        unsigned char *buf_tmp = malloc(SPX_ADDR_BYTES + SPX_N);
        unsigned char *out_tmp = malloc(SPX_N);
        if (!buf_tmp || !out_tmp) {
            if (buf_tmp) free(buf_tmp);
            if (out_tmp) free(out_tmp);
            return;
        }
        memset(buf_tmp, 0, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp, addr, SPX_ADDR_BYTES);
        haraka256(out_tmp, buf_tmp, ctx);
        memcpy(bitmask_out, out_tmp, SPX_N);
        free(buf_tmp);
        free(out_tmp);
    } else {
        haraka_S(bitmask_out, inblocks * SPX_N, (unsigned char *)addr, SPX_ADDR_BYTES, ctx);
    }
}

void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    unsigned int i;
    if (inblocks == 1) {
        /* Use dynamic allocation to support larger SPX_N values */
        unsigned char *buf_tmp = malloc(SPX_ADDR_BYTES + SPX_N);
        unsigned char *out_tmp = malloc(SPX_N);
        if (!buf_tmp || !out_tmp) {
            if (buf_tmp) free(buf_tmp);
            if (out_tmp) free(out_tmp);
            return;
        }
        memset(buf_tmp, 0, SPX_ADDR_BYTES + SPX_N);
        memcpy(buf_tmp, addr, SPX_ADDR_BYTES);
        for (i = 0; i < SPX_N; i++) {
            buf_tmp[SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
        }
        haraka512(out_tmp, buf_tmp, ctx);
        memcpy(out, out_tmp, SPX_N);
        free(buf_tmp);
        free(out_tmp);
    } else {
        SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
        memcpy(buf, addr, SPX_ADDR_BYTES);
        for (i = 0; i < inblocks * SPX_N; i++) {
            buf[SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
        }
        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N, ctx);
    }
}
