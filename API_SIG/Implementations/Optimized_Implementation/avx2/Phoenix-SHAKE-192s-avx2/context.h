#ifndef PH_CONTEXT_H
#define PH_CONTEXT_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint8_t pub_seed[PH_N];
    uint8_t sk_seed[PH_N];

#ifdef PH_SM3
    // sm3 state that absorbed pub_seed
    uint8_t state_seeded_sm3[40];
#endif

#ifdef PH_SHAKE
    // shake256 state that absorbed pub_seed
    uint64_t state_seeded_shake[26];
#endif

    // Always include these to allow Haraka unit tests even when not the primary hash
    uint64_t tweaked512_rc64[10][8];
    uint32_t tweaked256_rc32[10][8];
} spx_ctx;

#endif
