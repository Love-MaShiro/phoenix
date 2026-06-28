#ifndef PH_PARAMS_H
#define PH_PARAMS_H

#define PH_NAMESPACE(s) PH_##s

/* Hash output length in bytes. */
#define PH_N 16
/* Height of the hypertree. */
#define PH_FULL_HEIGHT 68
/* Number of subtree layer. */
#define PH_D 17
/* TFORS tree dimensions. */
#define PH_TFORS_A 7
#define PH_TFORS_K_PRIME 32
#define PH_TFORS_LOG_K_PRIME 5
#define PH_TFORS_K 19
#define PH_TFORS_HEIGHT (PH_TFORS_LOG_K_PRIME + PH_TFORS_A)
#define PH_TFORS_T (1 << PH_TFORS_A)
/* Winternitz parameter, */
#define PH_GWOTSC_W1 8
#define PH_GWOTSC_LOGW1 3
#define PH_GWOTSC_W2 16
#define PH_GWOTSC_LOGW2 4

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define PH_ADDR_BYTES 32

#define PH_GWOTSC_W1_LEN 20
#define PH_GWOTSC_W2_LEN 17
#define PH_GWOTSC_LEN1 (PH_GWOTSC_W1_LEN + PH_GWOTSC_W2_LEN)

/* PH_GWOTSC_LEN2 is fixed */
#define PH_GWOTSC_LEN2 1

#define PH_GWOTSC_LEN (PH_GWOTSC_LEN1 + PH_GWOTSC_LEN2)
#define PH_GWOTSC_BYTES (PH_GWOTSC_LEN * PH_N)
#define PH_GWOTSC_PK_BYTES PH_GWOTSC_BYTES

/* Subtree size. */
#define PH_TREE_HEIGHT (PH_FULL_HEIGHT / PH_D)

#if PH_TREE_HEIGHT * PH_D != PH_FULL_HEIGHT
#error PH_D should always divide PH_FULL_HEIGHT
#endif

/* TFORS parameters. */
#define PH_TFORS_MSG_BYTES ((PH_TFORS_A * PH_TFORS_K + 7) / 8 + PH_N)
#define PH_TFORS_BYTES (PH_TFORS_K * PH_N + \
                         PH_TFORS_K * PH_TFORS_HEIGHT * PH_N)
#define PH_TFORS_SIG_MAX 2436
#define PH_TFORS_PK_BYTES PH_N

/* custom upgrade parameter definitions */
#define COUNTER_SIZE 4


/* --- GWOTS+C Automatic Parameter Calculation --- */
/* Winternitz parameter for the single checksum chain */
#define PH_GWOTSC_CHECKSUM_W 16
#define PH_GWOTSC_CHECKSUM_LOGW 4

/*
 * Calculate the expected average sum (E) of the message chains.
 * Formula: E = Sum of (Length_i * (W_i - 1) / 2)
 * We multiply by Length first to avoid floating point issues in macros.
 */
#define GWOTSC_EXPECTED_SUM (                   \
    ((PH_GWOTSC_W1_LEN * (PH_GWOTSC_W1 - 1)) +  \
     (PH_GWOTSC_W2_LEN * (PH_GWOTSC_W2 - 1))) / \
    2)

/*
 * GWOTSC_SUM_BASE: The starting point of the acceptable sum range.
 * We center the range around the expected average sum.
 */
#define GWOTSC_SUM_BASE (GWOTSC_EXPECTED_SUM - (PH_GWOTSC_CHECKSUM_W / 2))

/*
 * GWOTSC_SUM_RANGE: The total number of sum values covered by one checksum chain.
 * For a chain with Winternitz parameter W, it can represent W distinct values (0 to W-1).
 */
#define GWOTSC_SUM_RANGE ((PH_GWOTSC_CHECKSUM_W) - 1)

/*
 * Note: The valid sum interval is [GWOTSC_SUM_BASE, GWOTSC_SUM_BASE + GWOTSC_SUM_RANGE)
 * For n=128, W1=16, W2=32, W1_LEN=22, W2_LEN=8:
 * E = (22*15 + 8*31) / 2 = (330 + 248) / 2 = 289
 * BASE = 289 - 8 = 281
 * RANGE = 15
 */

/* Resulting PH sizes. */
#define PH_BYTES (PH_N + COUNTER_SIZE + PH_TFORS_SIG_MAX + PH_D * (PH_GWOTSC_BYTES + COUNTER_SIZE) + \
                   PH_FULL_HEIGHT * PH_N)
#define PH_PK_BYTES (2 * PH_N)
#define PH_SK_BYTES (2 * PH_N + PH_PK_BYTES)

#include "../shake_offsets.h"

#endif
