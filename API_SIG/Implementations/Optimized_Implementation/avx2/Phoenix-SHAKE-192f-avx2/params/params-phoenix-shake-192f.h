/* Phoenix-SHAKE-192f parameter definitions */

#ifndef PH_PARAMS_H
#define PH_PARAMS_H

#define PH_NAMESPACE(s) PH_##s

/* Hash output length in bytes. */
#define PH_N 24
/* Height of the hypertree. */
#define PH_FULL_HEIGHT 68
/* Number of subtree layer. */
#define PH_D 17
/* TFORS tree dimensions. */
#define PH_TFORS_A 8
#define PH_TFORS_K_PRIME 32
#define PH_TFORS_LOG_K_PRIME 5
#define PH_TFORS_K 29
#define PH_TFORS_HEIGHT (PH_TFORS_LOG_K_PRIME + PH_TFORS_A)
#define PH_TFORS_T (1 << PH_TFORS_A)
/* Winternitz parameter. */
#define PH_GWOTSC_W1 8
#define PH_GWOTSC_LOGW1 3
#define PH_GWOTSC_W2 16
#define PH_GWOTSC_LOGW2 4

/* Address length in bytes. */
#define PH_ADDR_BYTES 32

/* GWOTSC chain lengths. */
#define PH_GWOTSC_W1_LEN 36
#define PH_GWOTSC_W2_LEN 21
#define PH_GWOTSC_LEN1 (PH_GWOTSC_W1_LEN + PH_GWOTSC_W2_LEN)

/* Checksum chain length is fixed. */
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
#define PH_TFORS_SIG_MAX 5396
#define PH_TFORS_PK_BYTES PH_N

/* Counter size for GWOTSC. */
#define COUNTER_SIZE 4

/* GWOTSC checksum parameter. */
#define PH_GWOTSC_CHECKSUM_W 16
#define PH_GWOTSC_CHECKSUM_LOGW 4

/* Expected average sum of message chains. */
#define GWOTSC_EXPECTED_SUM (                   \
    ((PH_GWOTSC_W1_LEN * (PH_GWOTSC_W1 - 1)) +  \
     (PH_GWOTSC_W2_LEN * (PH_GWOTSC_W2 - 1))) / \
    2)

/* Acceptable sum range for counter search. */
#define GWOTSC_SUM_BASE (GWOTSC_EXPECTED_SUM - (PH_GWOTSC_CHECKSUM_W / 2))
#define GWOTSC_SUM_RANGE ((PH_GWOTSC_CHECKSUM_W) - 1)

/* Resulting Phoenix signature sizes. */
#define PH_BYTES (PH_N + COUNTER_SIZE + PH_TFORS_SIG_MAX + PH_D * (PH_GWOTSC_BYTES + COUNTER_SIZE) + \
                   PH_FULL_HEIGHT * PH_N)
#define PH_PK_BYTES (2 * PH_N)
#define PH_SK_BYTES (2 * PH_N + PH_PK_BYTES)

#include "../shake_offsets.h"

#endif /* PH_PARAMS_H */