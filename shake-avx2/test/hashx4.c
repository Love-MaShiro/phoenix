#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "hash.h"
#include "hashx4.h"
#include "params.h"

static void fill_ctx(spx_ctx *ctx)
{
    size_t i;

    for (i = 0; i < SPX_N; i++) {
        ctx->pub_seed[i] = (unsigned char)(0x10u + i);
        ctx->sk_seed[i] = (unsigned char)(0x80u + i);
    }
}

static void fill_addrx4(uint32_t addrx4[4 * 8])
{
    uint32_t addr[8];
    unsigned int lane;

    for (lane = 0; lane < 4; lane++) {
        memset(addr, 0, sizeof(addr));
        set_layer_addr(addr, lane);
        set_tree_addr(addr, 0x0102030405060708ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_WOTSPRF);
        set_keypair_addr(addr, 0x11223344U + lane);
        set_chain_addr(addr, (uint32_t)(3 * lane + 1));
        set_hash_addr(addr, (uint32_t)(5 * lane + 2));
        memcpy(addrx4 + lane * 8, addr, sizeof(addr));
    }
}

int main(void)
{
    spx_ctx ctx;
    uint32_t addrx4[4 * 8];
    unsigned char out0[SPX_N];
    unsigned char out1[SPX_N];
    unsigned char out2[SPX_N];
    unsigned char out3[SPX_N];
    unsigned char ref0[SPX_N];
    unsigned char ref1[SPX_N];
    unsigned char ref2[SPX_N];
    unsigned char ref3[SPX_N];

    fill_ctx(&ctx);
    fill_addrx4(addrx4);

    prf_addrx4(out0, out1, out2, out3, &ctx, addrx4);

    prf_addr(ref0, &ctx, addrx4 + 0 * 8);
    prf_addr(ref1, &ctx, addrx4 + 1 * 8);
    prf_addr(ref2, &ctx, addrx4 + 2 * 8);
    prf_addr(ref3, &ctx, addrx4 + 3 * 8);

    if (memcmp(out0, ref0, SPX_N) != 0 ||
        memcmp(out1, ref1, SPX_N) != 0 ||
        memcmp(out2, ref2, SPX_N) != 0 ||
        memcmp(out3, ref3, SPX_N) != 0) {
        fprintf(stderr, "prf_addrx4 output mismatch\n");
        return 1;
    }

    puts("prf_addrx4 matches 4x prf_addr");
    return 0;
}
