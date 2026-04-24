#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

#define SPX_NAMESPACE(s) SPX_##s

/* Hash output length in bytes. */
#define SPX_N 32
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 72
/* Number of subtree layer. */
#define SPX_D 12
/* TFORS tree dimensions. */
#define SPX_TFORS_A 10
#define SPX_TFORS_K_PRIME 32
#define SPX_TFORS_LOG_K_PRIME 5
#define SPX_TFORS_K 27
#define SPX_TFORS_HEIGHT (SPX_TFORS_LOG_K_PRIME + SPX_TFORS_A)
/* Winternitz parameter, */
#define SPX_WOTS_W1 16
#define SPX_WOTS_LOGW1 4
#define SPX_WOTS_W2 32
#define SPX_WOTS_LOGW2 5

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define SPX_ADDR_BYTES 32

#define SPX_WOTS_W1_LEN 64
#define SPX_WOTS_W2_LEN 0
#define SPX_WOTS_LEN1 (SPX_WOTS_W1_LEN + SPX_WOTS_W2_LEN)

/* SPX_WOTS_LEN2 is fixed */
#define SPX_WOTS_LEN2 1

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* TFORS parameters. */
#define SPX_TFORS_MSG_BYTES ((SPX_TFORS_A * SPX_TFORS_K + 7) / 8 + SPX_N)
#define SPX_TFORS_BYTES (SPX_TFORS_K * SPX_N + \
                         SPX_TFORS_K * SPX_TFORS_HEIGHT * SPX_N)
#define SPX_TFORS_SIG_MAX (SPX_TFORS_BYTES * 7) / 10
#define SPX_TFORS_PK_BYTES SPX_N

/* custom upgrade parameter definitions */
#define COUNTER_SIZE 4

/* Search and checksum range definition */
#define SPX_WOTS_ZERO_LAST_BITS 0
#define WOTS_ZERO_BITS SPX_WOTS_ZERO_LAST_BITS

/* --- WOTS+C Automatic Parameter Calculation --- */
/* Winternitz parameter for the single checksum chain */
#define SPX_WOTS_CHECKSUM_W 16
#define SPX_WOTS_CHECKSUM_LOGW 4

/*
 * Calculate the expected average sum (E) of the message chains.
 * Formula: E = Sum of (Length_i * (W_i - 1) / 2)
 * We multiply by Length first to avoid floating point issues in macros.
 */
#define WOTS_EXPECTED_SUM (                   \
    ((SPX_WOTS_W1_LEN * (SPX_WOTS_W1 - 1)) +  \
     (SPX_WOTS_W2_LEN * (SPX_WOTS_W2 - 1))) / \
    2)

/*
 * WOTS_SUM_BASE: The starting point of the acceptable sum range.
 * We center the range around the expected average sum.
 */
#define WOTS_SUM_BASE (WOTS_EXPECTED_SUM - (SPX_WOTS_CHECKSUM_W / 2))

/*
 * WOTS_SUM_RANGE: The total number of sum values covered by one checksum chain.
 * For a chain with Winternitz parameter W, it can represent W distinct values (0 to W-1).
 */
#define WOTS_SUM_RANGE ((SPX_WOTS_CHECKSUM_W) - 1)

/*
 * Note: The valid sum interval is [WOTS_SUM_BASE, WOTS_SUM_BASE + WOTS_SUM_RANGE)
 * For n=128, W1=16, W2=32, W1_LEN=22, W2_LEN=8:
 * E = (22*15 + 8*31) / 2 = (330 + 248) / 2 = 289
 * BASE = 289 - 8 = 281
 * RANGE = 15
 */

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + COUNTER_SIZE + SPX_TFORS_SIG_MAX + SPX_D * (SPX_WOTS_BYTES + COUNTER_SIZE) + \
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

#include "../shake_offsets.h"

#endif