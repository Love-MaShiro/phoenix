#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "params.h"
#include "thash.h"
#include "thashx4.h"

static void fill_ctx(spx_ctx *ctx)
{
    size_t i;

    for (i = 0; i < SPX_N; i++) {
        ctx->pub_seed[i] = (unsigned char)(0x21u + i);
        ctx->sk_seed[i] = (unsigned char)(0x90u + i);
    }
}

static void fill_addrx4(uint32_t addrx4[4 * 8])
{
    uint32_t addr[8];
    unsigned int lane;

    for (lane = 0; lane < 4; lane++) {
        memset(addr, 0, sizeof(addr));
        set_layer_addr(addr, lane + 1);
        set_tree_addr(addr, 0x0F0E0D0C0B0A0908ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_HASHTREE);
        set_tree_height(addr, lane + 2);
        set_tree_index(addr, 100 + 7 * lane);
        memcpy(addrx4 + lane * 8, addr, sizeof(addr));
    }
}

static void fill_inputs(unsigned char *in0,
                        unsigned char *in1,
                        unsigned char *in2,
                        unsigned char *in3,
                        unsigned int total_bytes)
{
    unsigned int i;

    for (i = 0; i < total_bytes; i++) {
        in0[i] = (unsigned char)(0x10u + (i % 251u));
        in1[i] = (unsigned char)(0x20u + (i % 241u));
        in2[i] = (unsigned char)(0x30u + (i % 239u));
        in3[i] = (unsigned char)(0x40u + (i % 233u));
    }
}

static int check_case(unsigned int inblocks)
{
    spx_ctx ctx;
    uint32_t addrx4[4 * 8];
    uint32_t addr0[8];
    uint32_t addr1[8];
    uint32_t addr2[8];
    uint32_t addr3[8];
    unsigned char in0[SPX_WOTS_LEN * SPX_N];
    unsigned char in1[SPX_WOTS_LEN * SPX_N];
    unsigned char in2[SPX_WOTS_LEN * SPX_N];
    unsigned char in3[SPX_WOTS_LEN * SPX_N];
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
    fill_inputs(in0, in1, in2, in3, SPX_WOTS_LEN * SPX_N);

    memcpy(addr0, addrx4 + 0 * 8, sizeof(addr0));
    memcpy(addr1, addrx4 + 1 * 8, sizeof(addr1));
    memcpy(addr2, addrx4 + 2 * 8, sizeof(addr2));
    memcpy(addr3, addrx4 + 3 * 8, sizeof(addr3));

    thashx4(out0, out1, out2, out3,
            in0, in1, in2, in3, inblocks, &ctx, addrx4);

    thash(ref0, in0, inblocks, &ctx, addr0);
    thash(ref1, in1, inblocks, &ctx, addr1);
    thash(ref2, in2, inblocks, &ctx, addr2);
    thash(ref3, in3, inblocks, &ctx, addr3);

    if (memcmp(out0, ref0, SPX_N) != 0 ||
        memcmp(out1, ref1, SPX_N) != 0 ||
        memcmp(out2, ref2, SPX_N) != 0 ||
        memcmp(out3, ref3, SPX_N) != 0) {
        fprintf(stderr, "thashx4 mismatch for inblocks=%u\n", inblocks);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (check_case(1) != 0 || check_case(2) != 0 || check_case(SPX_WOTS_LEN) != 0) {
        return 1;
    }

    puts("thashx4 matches 4x thash");
    return 0;
}
