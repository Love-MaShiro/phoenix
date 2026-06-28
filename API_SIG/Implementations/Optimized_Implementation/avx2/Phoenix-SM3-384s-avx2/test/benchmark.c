#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "../hash.h"
#include "../hash_sm3.h"
#include "../thash.h"
#include "../api.h"
#include "../tfors.h"
#include "../wotsx1.h"
#include "../params.h"
#include "../randombytes.h"
#include "cycles.h"

#define SPX_MLEN 32
#define NTESTS 10

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx* ctx,
                uint32_t addr[8]);
static void bench_sm3_xof4_scalar(unsigned char *out0, unsigned char *out1,
                                  unsigned char *out2, unsigned char *out3,
                                  const unsigned char *in0,
                                  const unsigned char *in1,
                                  const unsigned char *in2,
                                  const unsigned char *in3,
                                  unsigned long outlen,
                                  unsigned long inlen);
static void bench_sm3_xofx4(unsigned char *out0, unsigned char *out1,
                            unsigned char *out2, unsigned char *out3,
                            const unsigned char *in0,
                            const unsigned char *in1,
                            const unsigned char *in2,
                            const unsigned char *in3,
                            unsigned long outlen,
                            unsigned long inlen);
static double now_us(void);

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}


static void printfcomma (unsigned long long n)
{
    if (n < 1000) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf (",%03llu", n % 1000);
}

static void printfalignedcomma (unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;
    }
    i = i/3 - 1;
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul*med, 12);
    printf(" cycles\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)\
    printf(TEXT);\
    start_us = now_us();\
    for(i = 0; i < NTESTS; i++) {\
        t[i] = cpucycles() / CORR;\
        FNCALL;\
    }\
    t[NTESTS] = cpucycles();\
    stop_us = now_us();\
    result = (stop_us - start_us) / (double)CORR;\
    display_result(result, t, NTESTS, MUL);
#define MEASURT(TEXT, MUL, FNCALL)\
    MEASURE_GENERIC(\
        TEXT, MUL,\
        do {\
          for (int j = 0; j < 1000; j++) {\
            FNCALL;\
          }\
        } while (0);,\
    1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)


int main(void)
{
    setbuf(stdout, NULL);
    init_cpucycles();

    spx_ctx ctx;

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);

    unsigned char tfors_pk[SPX_TFORS_PK_BYTES];
    unsigned char tfors_m[SPX_TFORS_MSG_BYTES];
    unsigned char tfors_sig[SPX_TFORS_BYTES];
    uint32_t addr[8];
    unsigned char block[SPX_N];
    unsigned char xof_in0[SPX_SM3_ADDR_BYTES + 2 * SPX_N];
    unsigned char xof_in1[SPX_SM3_ADDR_BYTES + 2 * SPX_N];
    unsigned char xof_in2[SPX_SM3_ADDR_BYTES + 2 * SPX_N];
    unsigned char xof_in3[SPX_SM3_ADDR_BYTES + 2 * SPX_N];
    unsigned char xof_out0[2 * SPX_N];
    unsigned char xof_out1[2 * SPX_N];
    unsigned char xof_out2[2 * SPX_N];
    unsigned char xof_out3[2 * SPX_N];

    unsigned char wots_pk[SPX_WOTS_PK_BYTES];

    unsigned long long smlen;
    unsigned long long mlen;
    unsigned long long slen;
    unsigned long long tfslen;
    unsigned long long t[NTESTS+1];
    double start_us, stop_us;
    double result;
    int i;

    randombytes(m, SPX_MLEN);
    randombytes((unsigned char *)addr, SPX_ADDR_BYTES);
    randombytes(tfors_m, SPX_TFORS_MSG_BYTES);
    randombytes(xof_in0, sizeof(xof_in0));
    randombytes(xof_in1, sizeof(xof_in1));
    randombytes(xof_in2, sizeof(xof_in2));
    randombytes(xof_in3, sizeof(xof_in3));

    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    initialize_hash_function(&ctx);

    uint32_t tfors_indices[SPX_TFORS_K];
    message_to_indices(tfors_indices, tfors_m, &ctx);

    printf("===============================================================\n");
    printf("Phoenix End-to-End Benchmark\n");
    printf("Parameter set: %s\n", PARAMNAME);
    printf("Parameters: n = %d, h = %d, d = %d, a = %d, k = %d, w = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_TFORS_A, SPX_TFORS_K,
           SPX_WOTS_W1);

    printf("Running %d iterations.\n", NTESTS);

    MEASURT("thash                ", 1, thash(block, block, 1, &ctx, addr));
    MEASURT("sm3_xof scalar x4    ", 1,
            bench_sm3_xof4_scalar(xof_out0, xof_out1, xof_out2, xof_out3,
                                  xof_in0, xof_in1, xof_in2, xof_in3,
                                  SPX_N, sizeof(xof_in0)));
    MEASURT("sm3_xofx4            ", 1,
            bench_sm3_xofx4(xof_out0, xof_out1, xof_out2, xof_out3,
                            xof_in0, xof_in1, xof_in2, xof_in3,
                            SPX_N, sizeof(xof_in0)));
    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair(pk, sk));
    MEASURE("  - WOTS pk gen..    ", (1 << SPX_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, addr));
    MEASURE("Signing..            ", 1, crypto_sign(sm, &smlen, &slen, &tfslen, m, SPX_MLEN, sk));
    MEASURE("  - WOTS pk gen..    ", SPX_D * (1 << SPX_TREE_HEIGHT), wots_gen_pkx1(wots_pk, &ctx, addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open(mout, &mlen, &slen, &tfslen, sm, smlen, pk));

    printf("Signature size: %llu bytes\n", smlen);
    printf("Public key size: %d bytes\n", SPX_PK_BYTES);
    printf("Secret key size: %d bytes\n", SPX_SK_BYTES);

    free(m);
    free(sm);
    free(mout);

    return 0;
}

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx *ctx,
                  uint32_t addr[8]) {
    struct leaf_info_x1 leaf;
    unsigned steps[ SPX_WOTS_LEN ] = { 0 };
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    wots_gen_leafx1(pk, ctx, 0, &leaf);
}

static void bench_sm3_xof4_scalar(unsigned char *out0, unsigned char *out1,
                                  unsigned char *out2, unsigned char *out3,
                                  const unsigned char *in0,
                                  const unsigned char *in1,
                                  const unsigned char *in2,
                                  const unsigned char *in3,
                                  unsigned long outlen,
                                  unsigned long inlen)
{
    sm3_xof(out0, outlen, in0, inlen);
    sm3_xof(out1, outlen, in1, inlen);
    sm3_xof(out2, outlen, in2, inlen);
    sm3_xof(out3, outlen, in3, inlen);
}

static void bench_sm3_xofx4(unsigned char *out0, unsigned char *out1,
                            unsigned char *out2, unsigned char *out3,
                            const unsigned char *in0,
                            const unsigned char *in1,
                            const unsigned char *in2,
                            const unsigned char *in3,
                            unsigned long outlen,
                            unsigned long inlen)
{
    sm3_xofx4(out0, out1, out2, out3, outlen,
              in0, in1, in2, in3, inlen);
}

static double now_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
#endif
}
