#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../address.h"
#include "../fips202.h"
#include "../hash.h"
#include "../hashx4.h"
#include "../params.h"
#include "../randombytes.h"
#include "../thash.h"
#include "../thashx4.h"
#include "../utilsx4.h"
#include "../wotsx1.h"
#include "cycles.h"

#define NTESTS 200

static int cmp_llu(const void *a, const void *b)
{
    if (*(const unsigned long long *)a < *(const unsigned long long *)b) return -1;
    if (*(const unsigned long long *)a > *(const unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if ((llen % 2u) != 0u) return l[llen / 2u];
    return (l[llen / 2u - 1u] + l[llen / 2u]) / 2u;
}

static void delta(unsigned long long *l, size_t llen)
{
    for (size_t i = 0; i + 1u < llen; i++) {
        l[i] = l[i + 1u] - l[i];
    }
}

static void printfcomma(unsigned long long n)
{
    if (n < 1000u) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000u);
    printf(",%03llu", n % 1000u);
}

static void printfalignedcomma(unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9u) {
        len -= 1;
        ncopy /= 10u;
        i += 1;
    }
    i = i / 3 - 1;
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result,
                           unsigned long long *l,
                           size_t llen,
                           unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1u);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul * med, 12);
    printf(" cycles\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)           \
    printf(TEXT);                                          \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);       \
    for (i = 0; i < NTESTS; i++) {                         \
        t[i] = cpucycles() / (CORR);                       \
        FNCALL;                                            \
    }                                                      \
    t[NTESTS] = cpucycles();                               \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);        \
    result = ((double)(stop.tv_sec - start.tv_sec) * 1e6 + \
              (double)(stop.tv_nsec - start.tv_nsec) / 1e3) / \
             (double)(CORR);                               \
    display_result(result, t, NTESTS, MUL)

#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

static void gen_chain_ref(unsigned char *out,
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

int main(void)
{
    spx_ctx ctx;
    uint32_t addr[8] = {0};
    uint32_t addrx4[4 * 8] = {0};
    uint32_t leaf_addr[8] = {0};
    unsigned char in0[SPX_WOTS_BYTES];
    unsigned char in1[SPX_WOTS_BYTES];
    unsigned char in2[SPX_WOTS_BYTES];
    unsigned char in3[SPX_WOTS_BYTES];
    unsigned char out0[SPX_N];
    unsigned char out1[SPX_N];
    unsigned char out2[SPX_N];
    unsigned char out3[SPX_N];
    unsigned char block[SPX_N];
    unsigned char leafx1[SPX_N];
    unsigned char leafx4[4 * SPX_N];
    unsigned char sig_dummy[SPX_WOTS_BYTES];
    unsigned char chain_in[4 * SPX_N];
    unsigned char chain_out[4 * SPX_N];
    unsigned int start_steps[4] = {0u, 0u, 0u, 0u};
    unsigned int chain_steps[4] = {5u, 7u, 3u, 6u};
    unsigned steps[SPX_WOTS_LEN];
    struct leaf_info_x1 info_x1;
    struct leaf_info_x4 info_x4;
    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    int i;

    setbuf(stdout, NULL);
    init_cpucycles();

    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    initialize_hash_function(&ctx);

    randombytes(in0, sizeof(in0));
    randombytes(in1, sizeof(in1));
    randombytes(in2, sizeof(in2));
    randombytes(in3, sizeof(in3));
    randombytes(chain_in, sizeof(chain_in));
    memset(sig_dummy, 0, sizeof(sig_dummy));

    set_layer_addr(addr, 1);
    set_tree_addr(addr, 0x1122334455667788ULL);
    set_type(addr, SPX_ADDR_TYPE_HASHTREE);
    set_tree_height(addr, 3);
    set_tree_index(addr, 5);

    for (uint32_t lane = 0; lane < 4; lane++) {
        memcpy(addrx4 + lane * 8, addr, SPX_ADDR_BYTES);
        set_tree_index(addrx4 + lane * 8, 5u + lane);
    }

    set_layer_addr(leaf_addr, 2);
    set_tree_addr(leaf_addr, 0x2233445566778899ULL);
    set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

    for (unsigned int k = 0; k < SPX_WOTS_LEN; k++) {
        steps[k] = valid_wots_step(k);
    }

    INITIALIZE_LEAF_INFO_X1(info_x1, leaf_addr, steps);
    info_x1.wots_sig = sig_dummy;
    info_x1.wots_sign_leaf = 17u;

    INITIALIZE_LEAF_INFO_X4(info_x4, leaf_addr, steps);
    info_x4.wots_sig = sig_dummy;
    info_x4.wots_sign_leaf = 17u;

    printf("===============================================================\n");
    printf("shake-avx2 X4 Microbenchmark\n");
    printf("Parameter set: %s\n", PARAMNAME);
    printf("Running %d iterations.\n", NTESTS);

    MEASURE("prf_addr x1........... ", 1,
            prf_addr(block, &ctx, addr));

    MEASURE("prf_addrx4............ ", 4,
            prf_addrx4(out0, out1, out2, out3, &ctx, addrx4));

    MEASURE("thash[1] x1........... ", 1,
            thash(block, in0, 1, &ctx, addr));

    MEASURE("thashx4[1]............ ", 4,
            thashx4(out0, out1, out2, out3, in0, in1, in2, in3, 1, &ctx, addrx4));

    MEASURE("thash[WOTS_LEN] x1.... ", 1,
            thash(block, in0, SPX_WOTS_LEN, &ctx, addr));

    MEASURE("thashx4[WOTS_LEN]..... ", 4,
            thashx4(out0, out1, out2, out3,
                    in0, in1, in2, in3, SPX_WOTS_LEN, &ctx, addrx4));

    MEASURE("chain x1.............. ", 1, {
        uint32_t chain_addr[8];
        memcpy(chain_addr, leaf_addr, sizeof(chain_addr));
        set_type(chain_addr, SPX_ADDR_TYPE_WOTS);
        set_keypair_addr(chain_addr, 9);
        set_chain_addr(chain_addr, 0);
        set_hash_addr(chain_addr, 0);
        gen_chain_ref(block, chain_in + 0 * SPX_N, 0, 5, &ctx, chain_addr, SPX_WOTS_W1);
    });

    MEASURE("chainx4............... ", 4, {
        uint32_t chain_addrx4[4 * 8];
        for (uint32_t lane = 0; lane < 4; lane++) {
            memcpy(chain_addrx4 + lane * 8, leaf_addr, SPX_ADDR_BYTES);
            set_type(chain_addrx4 + lane * 8, SPX_ADDR_TYPE_WOTS);
            set_keypair_addr(chain_addrx4 + lane * 8, 9u + lane);
            set_chain_addr(chain_addrx4 + lane * 8, 0);
            set_hash_addr(chain_addrx4 + lane * 8, 0);
        }
        chainx4(chain_out + 0 * SPX_N,
                chain_out + 1 * SPX_N,
                chain_out + 2 * SPX_N,
                chain_out + 3 * SPX_N,
                chain_in + 0 * SPX_N,
                chain_in + 1 * SPX_N,
                chain_in + 2 * SPX_N,
                chain_in + 3 * SPX_N,
                start_steps, chain_steps, &ctx, chain_addrx4, SPX_WOTS_W1);
    });

    MEASURE("gen_leaf x1........... ", 1,
            wots_gen_leafx1(leafx1, &ctx, 16u, &info_x1));

    MEASURE("gen_leafx4............ ", 4,
            gen_leafx4(leafx4, &ctx, 16u, &info_x4));

    printf("===============================================================\n");
    return 0;
}
