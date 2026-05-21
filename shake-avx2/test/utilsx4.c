#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../address.h"
#include "../context.h"
#include "../params.h"
#include "../thash.h"
#include "../utilsx1.h"
#include "../utilsx4.h"
#include "../wotsx1.h"

static void fill_ctx(spx_ctx *ctx)
{
    size_t i;

    for (i = 0; i < SPX_N; i++) {
        ctx->pub_seed[i] = (unsigned char)(0x31u + i);
        ctx->sk_seed[i] = (unsigned char)(0xA0u + i);
    }
}

static void ref_gen_chain(unsigned char *out,
                          const unsigned char *in,
                          unsigned int start,
                          unsigned int steps,
                          const spx_ctx *ctx,
                          uint32_t addr[8],
                          uint32_t w)
{
    memcpy(out, in, SPX_N);

    for (uint32_t i = start; i < start + steps && i < w; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

static int test_chainx4(void)
{
    spx_ctx ctx;
    uint32_t addrx4[4 * 8] = {0};
    uint32_t ref_addr0[8];
    uint32_t ref_addr1[8];
    uint32_t ref_addr2[8];
    uint32_t ref_addr3[8];
    unsigned char in0[SPX_N];
    unsigned char in1[SPX_N];
    unsigned char in2[SPX_N];
    unsigned char in3[SPX_N];
    unsigned char out0[SPX_N];
    unsigned char out1[SPX_N];
    unsigned char out2[SPX_N];
    unsigned char out3[SPX_N];
    unsigned char ref0[SPX_N];
    unsigned char ref1[SPX_N];
    unsigned char ref2[SPX_N];
    unsigned char ref3[SPX_N];
    unsigned int start[4] = {0, 1, 2, 0};
    unsigned int steps[4] = {5, 3, 1, 7};
    uint32_t w = SPX_WOTS_W1;

    fill_ctx(&ctx);
    for (unsigned int i = 0; i < SPX_N; i++) {
        in0[i] = (unsigned char)(0x10u + i);
        in1[i] = (unsigned char)(0x20u + i);
        in2[i] = (unsigned char)(0x30u + i);
        in3[i] = (unsigned char)(0x40u + i);
    }

    for (unsigned int lane = 0; lane < 4; lane++) {
        uint32_t *addr = addrx4 + lane * 8;
        set_layer_addr(addr, lane);
        set_tree_addr(addr, 0x0102030405060708ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_WOTS);
        set_keypair_addr(addr, 7 + lane);
        set_chain_addr(addr, 3);
        set_hash_addr(addr, 0);
    }

    memcpy(ref_addr0, addrx4 + 0 * 8, sizeof(ref_addr0));
    memcpy(ref_addr1, addrx4 + 1 * 8, sizeof(ref_addr1));
    memcpy(ref_addr2, addrx4 + 2 * 8, sizeof(ref_addr2));
    memcpy(ref_addr3, addrx4 + 3 * 8, sizeof(ref_addr3));

    chainx4(out0, out1, out2, out3,
            in0, in1, in2, in3,
            start, steps, &ctx, addrx4, w);

    ref_gen_chain(ref0, in0, start[0], steps[0], &ctx, ref_addr0, w);
    ref_gen_chain(ref1, in1, start[1], steps[1], &ctx, ref_addr1, w);
    ref_gen_chain(ref2, in2, start[2], steps[2], &ctx, ref_addr2, w);
    ref_gen_chain(ref3, in3, start[3], steps[3], &ctx, ref_addr3, w);

    if (memcmp(out0, ref0, SPX_N) != 0 ||
        memcmp(out1, ref1, SPX_N) != 0 ||
        memcmp(out2, ref2, SPX_N) != 0 ||
        memcmp(out3, ref3, SPX_N) != 0) {
        fprintf(stderr, "chainx4 mismatch\n");
        return 1;
    }

    return 0;
}

static unsigned int valid_wots_step(unsigned int i)
{
    if (i < SPX_WOTS_W1_LEN) {
        return i % SPX_WOTS_W1;
    }
    if (i < SPX_WOTS_LEN1) {
        return i % SPX_WOTS_W2;
    }
    return i % SPX_WOTS_CHECKSUM_W;
}

static int test_gen_leafx4(void)
{
    spx_ctx ctx;
    uint32_t base_addr[8] = {0};
    unsigned char leaves4[4 * SPX_N];
    unsigned char ref_leaves[4 * SPX_N];
    unsigned char sig4[SPX_WOTS_BYTES];
    unsigned char ref_sig[SPX_WOTS_BYTES];
    unsigned steps[SPX_WOTS_LEN];
    struct leaf_info_x4 info4;
    uint32_t base_leaf = 12;

    fill_ctx(&ctx);
    set_layer_addr(base_addr, 1);
    set_tree_addr(base_addr, 0x0A0B0C0D0E0F0011ULL);
    set_type(base_addr, SPX_ADDR_TYPE_WOTS);

    for (unsigned int i = 0; i < SPX_WOTS_LEN; i++) {
        steps[i] = valid_wots_step(i);
    }

    memset(sig4, 0, sizeof(sig4));
    memset(ref_sig, 0, sizeof(ref_sig));

    INITIALIZE_LEAF_INFO_X4(info4, base_addr, steps);
    info4.wots_sig = sig4;
    info4.wots_sign_leaf = base_leaf + 2;

    gen_leafx4(leaves4, &ctx, base_leaf, &info4);

    for (unsigned int lane = 0; lane < 4; lane++) {
        struct leaf_info_x1 info1;
        uint32_t addr_copy[8];

        memcpy(addr_copy, base_addr, sizeof(addr_copy));
        INITIALIZE_LEAF_INFO_X1(info1, addr_copy, steps);
        info1.wots_sig = ref_sig;
        info1.wots_sign_leaf = base_leaf + 2;

        wots_gen_leafx1(ref_leaves + lane * SPX_N, &ctx, base_leaf + lane, &info1);
    }

    if (memcmp(leaves4, ref_leaves, sizeof(leaves4)) != 0) {
        fprintf(stderr, "gen_leafx4 leaf mismatch\n");
        return 1;
    }

    if (memcmp(sig4, ref_sig, sizeof(sig4)) != 0) {
        fprintf(stderr, "gen_leafx4 signature mismatch\n");
        return 1;
    }

    return 0;
}

static int test_treehashx4(void)
{
    spx_ctx ctx;
    uint32_t base_wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t tree_addrx4[4 * 8];
    unsigned char root1[SPX_N];
    unsigned char root4[SPX_N];
    unsigned char auth1[SPX_TREE_HEIGHT * SPX_N];
    unsigned char auth4[SPX_TREE_HEIGHT * SPX_N];
    unsigned char sig1[SPX_WOTS_BYTES];
    unsigned char sig4[SPX_WOTS_BYTES];
    unsigned steps[SPX_WOTS_LEN];
    struct leaf_info_x1 info1;
    struct leaf_info_x4 info4;
    uint32_t leaf_idx = 9;

    fill_ctx(&ctx);
    set_layer_addr(base_wots_addr, 2);
    set_tree_addr(base_wots_addr, 0x0011223344556677ULL);
    set_type(base_wots_addr, SPX_ADDR_TYPE_WOTS);

    set_layer_addr(tree_addr, 2);
    set_tree_addr(tree_addr, 0x0011223344556677ULL);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    for (unsigned int lane = 0; lane < 4; lane++) {
        memcpy(tree_addrx4 + lane * 8, tree_addr, SPX_ADDR_BYTES);
    }

    for (unsigned int i = 0; i < SPX_WOTS_LEN; i++) {
        steps[i] = valid_wots_step(i);
    }

    memset(sig1, 0, sizeof(sig1));
    memset(sig4, 0, sizeof(sig4));

    INITIALIZE_LEAF_INFO_X1(info1, base_wots_addr, steps);
    info1.wots_sig = sig1;
    info1.wots_sign_leaf = leaf_idx;

    INITIALIZE_LEAF_INFO_X4(info4, base_wots_addr, steps);
    info4.wots_sig = sig4;
    info4.wots_sign_leaf = leaf_idx;

    treehashx1(root1, auth1, &ctx, leaf_idx, 0, SPX_TREE_HEIGHT,
               wots_gen_leafx1, tree_addr, &info1);
    treehashx4(root4, auth4, &ctx, leaf_idx, 0, SPX_TREE_HEIGHT,
               gen_leafx4, tree_addrx4, &info4);

    if (memcmp(root1, root4, SPX_N) != 0) {
        fprintf(stderr, "treehashx4 root mismatch\n");
        return 1;
    }

    if (memcmp(auth1, auth4, sizeof(auth1)) != 0) {
        fprintf(stderr, "treehashx4 auth path mismatch\n");
        return 1;
    }

    if (memcmp(sig1, sig4, sizeof(sig1)) != 0) {
        fprintf(stderr, "treehashx4 WOTS signature mismatch\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_chainx4() != 0 || test_gen_leafx4() != 0 || test_treehashx4() != 0) {
        return 1;
    }

    puts("utilsx4 matches single-lane reference");
    return 0;
}
