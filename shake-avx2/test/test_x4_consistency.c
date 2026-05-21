#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../address.h"
#include "../api.h"
#include "../context.h"
#include "../fips202.h"
#include "../fips202x4.h"
#include "../hash.h"
#include "../hashx4.h"
#include "../params.h"
#include "../rng.h"
#include "../thash.h"
#include "../thashx4.h"
#include "../utilsx4.h"
#include "../wotsx1.h"
#include "test_x4_consistency_vectors.h"

#define LANE_NONE (-1)

static int compare_bytes(const char *func_name,
                         int lane,
                         const unsigned char *got,
                         const unsigned char *expected,
                         size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (got[i] != expected[i]) {
            fprintf(stderr,
                    "%s mismatch: lane=%d offset=%zu got=%02x expected=%02x\n",
                    func_name, lane, i, got[i], expected[i]);
            return -1;
        }
    }

    return 0;
}

static int compare_size_value(const char *func_name,
                              int lane,
                              size_t got,
                              size_t expected)
{
    if (got != expected) {
        fprintf(stderr,
                "%s mismatch: lane=%d offset=0 got=%zu expected=%zu\n",
                func_name, lane, got, expected);
        return -1;
    }

    return 0;
}

static void fill_ctx(spx_ctx *ctx)
{
    size_t i;

    for (i = 0; i < SPX_N; i++) {
        ctx->pub_seed[i] = (unsigned char)(0x21u + i);
        ctx->sk_seed[i] = (unsigned char)(0x71u + i);
    }
}

static void fill_pattern(unsigned char *buf, size_t len, unsigned char base)
{
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char)(base + (unsigned char)i);
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

static int test_shake256x4(void)
{
    unsigned char in0[96];
    unsigned char in1[96];
    unsigned char in2[96];
    unsigned char in3[96];
    unsigned char out0[64];
    unsigned char out1[64];
    unsigned char out2[64];
    unsigned char out3[64];
    unsigned char ref0[64];
    unsigned char ref1[64];
    unsigned char ref2[64];
    unsigned char ref3[64];

    fill_pattern(in0, sizeof(in0), 0x10u);
    fill_pattern(in1, sizeof(in1), 0x30u);
    fill_pattern(in2, sizeof(in2), 0x50u);
    fill_pattern(in3, sizeof(in3), 0x70u);

    shake256x4(out0, out1, out2, out3, sizeof(out0),
               in0, in1, in2, in3, sizeof(in0));

    shake256(ref0, sizeof(ref0), in0, sizeof(in0));
    shake256(ref1, sizeof(ref1), in1, sizeof(in1));
    shake256(ref2, sizeof(ref2), in2, sizeof(in2));
    shake256(ref3, sizeof(ref3), in3, sizeof(in3));

    return compare_bytes("shake256x4", 0, out0, ref0, sizeof(out0)) ||
           compare_bytes("shake256x4", 1, out1, ref1, sizeof(out1)) ||
           compare_bytes("shake256x4", 2, out2, ref2, sizeof(out2)) ||
           compare_bytes("shake256x4", 3, out3, ref3, sizeof(out3));
}

static int test_prf_addrx4(void)
{
    spx_ctx ctx;
    uint32_t addrx4[4 * 8] = {0};
    unsigned char out0[SPX_N];
    unsigned char out1[SPX_N];
    unsigned char out2[SPX_N];
    unsigned char out3[SPX_N];
    unsigned char ref0[SPX_N];
    unsigned char ref1[SPX_N];
    unsigned char ref2[SPX_N];
    unsigned char ref3[SPX_N];

    fill_ctx(&ctx);
    for (uint32_t lane = 0; lane < 4; lane++) {
        uint32_t *addr = addrx4 + lane * 8;
        set_layer_addr(addr, lane);
        set_tree_addr(addr, 0x0102030405060708ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_WOTSPRF);
        set_keypair_addr(addr, 9 + lane);
        set_chain_addr(addr, 2 + lane);
        set_hash_addr(addr, lane);
    }

    prf_addrx4(out0, out1, out2, out3, &ctx, addrx4);
    prf_addr(ref0, &ctx, addrx4 + 0 * 8);
    prf_addr(ref1, &ctx, addrx4 + 1 * 8);
    prf_addr(ref2, &ctx, addrx4 + 2 * 8);
    prf_addr(ref3, &ctx, addrx4 + 3 * 8);

    return compare_bytes("prf_addrx4", 0, out0, ref0, SPX_N) ||
           compare_bytes("prf_addrx4", 1, out1, ref1, SPX_N) ||
           compare_bytes("prf_addrx4", 2, out2, ref2, SPX_N) ||
           compare_bytes("prf_addrx4", 3, out3, ref3, SPX_N);
}

static int test_thashx4_case(unsigned int inblocks)
{
    spx_ctx ctx;
    unsigned char in0[SPX_WOTS_BYTES];
    unsigned char in1[SPX_WOTS_BYTES];
    unsigned char in2[SPX_WOTS_BYTES];
    unsigned char in3[SPX_WOTS_BYTES];
    unsigned char out0[SPX_N];
    unsigned char out1[SPX_N];
    unsigned char out2[SPX_N];
    unsigned char out3[SPX_N];
    unsigned char ref0[SPX_N];
    unsigned char ref1[SPX_N];
    unsigned char ref2[SPX_N];
    unsigned char ref3[SPX_N];
    uint32_t addrx4[4 * 8] = {0};
    uint32_t ref_addr0[8];
    uint32_t ref_addr1[8];
    uint32_t ref_addr2[8];
    uint32_t ref_addr3[8];
    size_t inlen = (size_t)inblocks * SPX_N;

    fill_ctx(&ctx);
    fill_pattern(in0, inlen, 0x11u);
    fill_pattern(in1, inlen, 0x33u);
    fill_pattern(in2, inlen, 0x55u);
    fill_pattern(in3, inlen, 0x77u);

    for (uint32_t lane = 0; lane < 4; lane++) {
        uint32_t *addr = addrx4 + lane * 8;
        set_layer_addr(addr, lane);
        set_tree_addr(addr, 0x1112131415161718ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_HASHTREE);
        set_tree_height(addr, 3 + lane);
        set_tree_index(addr, 7 + lane);
    }

    memcpy(ref_addr0, addrx4 + 0 * 8, sizeof(ref_addr0));
    memcpy(ref_addr1, addrx4 + 1 * 8, sizeof(ref_addr1));
    memcpy(ref_addr2, addrx4 + 2 * 8, sizeof(ref_addr2));
    memcpy(ref_addr3, addrx4 + 3 * 8, sizeof(ref_addr3));

    thashx4(out0, out1, out2, out3,
            in0, in1, in2, in3,
            inblocks, &ctx, addrx4);

    thash(ref0, in0, inblocks, &ctx, ref_addr0);
    thash(ref1, in1, inblocks, &ctx, ref_addr1);
    thash(ref2, in2, inblocks, &ctx, ref_addr2);
    thash(ref3, in3, inblocks, &ctx, ref_addr3);

    return compare_bytes("thashx4", 0, out0, ref0, SPX_N) ||
           compare_bytes("thashx4", 1, out1, ref1, SPX_N) ||
           compare_bytes("thashx4", 2, out2, ref2, SPX_N) ||
           compare_bytes("thashx4", 3, out3, ref3, SPX_N);
}

static int test_thashx4(void)
{
    return test_thashx4_case(1) ||
           test_thashx4_case(2) ||
           test_thashx4_case(SPX_WOTS_LEN);
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
    unsigned int steps[4] = {5, 3, 1, 0};
    uint32_t w = SPX_WOTS_W1;

    fill_ctx(&ctx);
    fill_pattern(in0, sizeof(in0), 0x09u);
    fill_pattern(in1, sizeof(in1), 0x19u);
    fill_pattern(in2, sizeof(in2), 0x29u);
    fill_pattern(in3, sizeof(in3), 0x39u);

    for (uint32_t lane = 0; lane < 4; lane++) {
        uint32_t *addr = addrx4 + lane * 8;
        set_layer_addr(addr, 1);
        set_tree_addr(addr, 0x2122232425262728ULL + lane);
        set_type(addr, SPX_ADDR_TYPE_WOTS);
        set_keypair_addr(addr, 4 + lane);
        set_chain_addr(addr, 5);
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

    return compare_bytes("chainx4", 0, out0, ref0, SPX_N) ||
           compare_bytes("chainx4", 1, out1, ref1, SPX_N) ||
           compare_bytes("chainx4", 2, out2, ref2, SPX_N) ||
           compare_bytes("chainx4", 3, out3, ref3, SPX_N);
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

    for (int lane = 0; lane < 4; lane++) {
        if (compare_bytes("gen_leafx4", lane,
                          leaves4 + lane * SPX_N,
                          ref_leaves + lane * SPX_N,
                          SPX_N) != 0) {
            return -1;
        }
    }

    return compare_bytes("gen_leafx4", LANE_NONE, sig4, ref_sig, SPX_WOTS_BYTES);
}

static int test_ref_compatibility(void)
{
#ifdef THASH_VARIANT_simple
    unsigned char pk_seed[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_seed[CRYPTO_SECRETKEYBYTES];
    unsigned char pk_rng[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_rng[CRYPTO_SECRETKEYBYTES];
    unsigned char *sig = malloc(CRYPTO_BYTES);
    size_t siglen = 0;
    size_t tfslen = 0;
    int verify_status;

    if (sig == NULL) {
        fprintf(stderr, "allocation failed: lane=%d offset=0\n", LANE_NONE);
        return -1;
    }

    if (crypto_sign_seed_keypair(pk_seed, sk_seed, vec_seed_keypair) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed: lane=%d offset=0\n", LANE_NONE);
        free(sig);
        return -1;
    }

    if (compare_bytes("crypto_sign_seed_keypair(pk)", LANE_NONE,
                      pk_seed, vec_pk_seed, sizeof(pk_seed)) != 0 ||
        compare_bytes("crypto_sign_seed_keypair(sk)", LANE_NONE,
                      sk_seed, vec_sk_seed, sizeof(sk_seed)) != 0) {
        free(sig);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_keypair(pk_rng, sk_rng) != 0) {
        fprintf(stderr, "crypto_sign_keypair failed: lane=%d offset=0\n", LANE_NONE);
        free(sig);
        return -1;
    }

    if (compare_bytes("crypto_sign_keypair(pk)", LANE_NONE,
                      pk_rng, vec_pk_rng, sizeof(pk_rng)) != 0 ||
        compare_bytes("crypto_sign_keypair(sk)", LANE_NONE,
                      sk_rng, vec_sk_rng, sizeof(sk_rng)) != 0) {
        free(sig);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_signature(sig, &siglen, &tfslen,
                              vec_msg, sizeof(vec_msg), vec_sk_rng) != 0) {
        fprintf(stderr, "crypto_sign_signature failed: lane=%d offset=0\n", LANE_NONE);
        free(sig);
        return -1;
    }

    if (compare_size_value("crypto_sign_signature(siglen)", LANE_NONE,
                           siglen, vec_siglen) != 0 ||
        compare_size_value("crypto_sign_signature(tfslen)", LANE_NONE,
                           tfslen, vec_tfslen) != 0 ||
        compare_bytes("crypto_sign_signature(sig)", LANE_NONE,
                      sig, vec_sig, vec_siglen) != 0) {
        free(sig);
        return -1;
    }

    verify_status = crypto_sign_verify(vec_sig, vec_siglen, vec_tfslen,
                                       vec_msg, sizeof(vec_msg), vec_pk_rng);
    if (verify_status != 0) {
        fprintf(stderr, "crypto_sign_verify failed: lane=%d offset=0\n", LANE_NONE);
        free(sig);
        return -1;
    }

    free(sig);
    return 0;
#else
    unsigned char pk_seed0[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_seed0[CRYPTO_SECRETKEYBYTES];
    unsigned char pk_seed1[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_seed1[CRYPTO_SECRETKEYBYTES];
    unsigned char pk_rng0[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_rng0[CRYPTO_SECRETKEYBYTES];
    unsigned char pk_rng1[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk_rng1[CRYPTO_SECRETKEYBYTES];
    unsigned char *sig_seed0 = malloc(CRYPTO_BYTES);
    unsigned char *sig_seed1 = malloc(CRYPTO_BYTES);
    unsigned char *sig_rng0 = malloc(CRYPTO_BYTES);
    unsigned char *sig_rng1 = malloc(CRYPTO_BYTES);
    size_t sig_seed_len0 = 0;
    size_t sig_seed_len1 = 0;
    size_t tfs_seed_len0 = 0;
    size_t tfs_seed_len1 = 0;
    size_t sig_rng_len0 = 0;
    size_t sig_rng_len1 = 0;
    size_t tfs_rng_len0 = 0;
    size_t tfs_rng_len1 = 0;

    if (sig_seed0 == NULL || sig_seed1 == NULL || sig_rng0 == NULL || sig_rng1 == NULL) {
        fprintf(stderr, "allocation failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (crypto_sign_seed_keypair(pk_seed0, sk_seed0, vec_seed_keypair) != 0 ||
        crypto_sign_seed_keypair(pk_seed1, sk_seed1, vec_seed_keypair) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (compare_bytes("crypto_sign_seed_keypair(pk)", LANE_NONE,
                      pk_seed0, pk_seed1, sizeof(pk_seed0)) != 0 ||
        compare_bytes("crypto_sign_seed_keypair(sk)", LANE_NONE,
                      sk_seed0, sk_seed1, sizeof(sk_seed0)) != 0) {
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_signature(sig_seed0, &sig_seed_len0, &tfs_seed_len0,
                              vec_msg, sizeof(vec_msg), sk_seed0) != 0) {
        fprintf(stderr, "crypto_sign_signature(seed) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_signature(sig_seed1, &sig_seed_len1, &tfs_seed_len1,
                              vec_msg, sizeof(vec_msg), sk_seed0) != 0) {
        fprintf(stderr, "crypto_sign_signature(seed repeat) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (compare_size_value("crypto_sign_signature(seed siglen)", LANE_NONE,
                           sig_seed_len0, sig_seed_len1) != 0 ||
        compare_size_value("crypto_sign_signature(seed tfslen)", LANE_NONE,
                           tfs_seed_len0, tfs_seed_len1) != 0 ||
        compare_bytes("crypto_sign_signature(seed sig)", LANE_NONE,
                      sig_seed0, sig_seed1, sig_seed_len0) != 0) {
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (crypto_sign_verify(sig_seed0, sig_seed_len0, tfs_seed_len0,
                           vec_msg, sizeof(vec_msg), pk_seed0) != 0) {
        fprintf(stderr, "crypto_sign_verify(seed) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_keypair(pk_rng0, sk_rng0) != 0) {
        fprintf(stderr, "crypto_sign_keypair failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_keypair(pk_rng1, sk_rng1) != 0) {
        fprintf(stderr, "crypto_sign_keypair repeat failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (compare_bytes("crypto_sign_keypair(pk)", LANE_NONE,
                      pk_rng0, pk_rng1, sizeof(pk_rng0)) != 0 ||
        compare_bytes("crypto_sign_keypair(sk)", LANE_NONE,
                      sk_rng0, sk_rng1, sizeof(sk_rng0)) != 0) {
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_signature(sig_rng0, &sig_rng_len0, &tfs_rng_len0,
                              vec_msg, sizeof(vec_msg), sk_rng0) != 0) {
        fprintf(stderr, "crypto_sign_signature(rng) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    randombytes_init((unsigned char *)vec_entropy, NULL);
    if (crypto_sign_signature(sig_rng1, &sig_rng_len1, &tfs_rng_len1,
                              vec_msg, sizeof(vec_msg), sk_rng0) != 0) {
        fprintf(stderr, "crypto_sign_signature(rng repeat) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (compare_size_value("crypto_sign_signature(rng siglen)", LANE_NONE,
                           sig_rng_len0, sig_rng_len1) != 0 ||
        compare_size_value("crypto_sign_signature(rng tfslen)", LANE_NONE,
                           tfs_rng_len0, tfs_rng_len1) != 0 ||
        compare_bytes("crypto_sign_signature(rng sig)", LANE_NONE,
                      sig_rng0, sig_rng1, sig_rng_len0) != 0) {
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    if (crypto_sign_verify(sig_rng0, sig_rng_len0, tfs_rng_len0,
                           vec_msg, sizeof(vec_msg), pk_rng0) != 0) {
        fprintf(stderr, "crypto_sign_verify(rng) failed: lane=%d offset=0\n", LANE_NONE);
        free(sig_seed0);
        free(sig_seed1);
        free(sig_rng0);
        free(sig_rng1);
        return -1;
    }

    free(sig_seed0);
    free(sig_seed1);
    free(sig_rng0);
    free(sig_rng1);
    return 0;
#endif
}

int main(void)
{
    if (test_shake256x4() != 0 ||
        test_prf_addrx4() != 0 ||
        test_thashx4() != 0 ||
        test_chainx4() != 0 ||
        test_gen_leafx4() != 0 ||
        test_ref_compatibility() != 0) {
        return 1;
    }

    puts("x4 consistency checks passed");
    return 0;
}
