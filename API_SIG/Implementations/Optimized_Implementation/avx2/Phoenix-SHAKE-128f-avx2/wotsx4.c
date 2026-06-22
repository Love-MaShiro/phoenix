#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "hashx4.h"
#include "thash.h"
#include "thashx4.h"
#include "wots.h"
#include "wotsx4.h"
#include "address.h"
#include "params.h"

/*
 * This generates 4 sequential WOTS public keys
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with one of these WOTS keys
 * Adapted for Phoenix dual Winternitz parameters (W1=16, W2=32)
 */
void wots_gen_leafx4(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x4 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, j, k;
    unsigned char pk_buffer[ 4 * SPX_WOTS_BYTES ];
    unsigned wots_offset = SPX_WOTS_BYTES;
    unsigned char *buffer;
    uint32_t wots_k_mask;
    unsigned wots_sign_index;

    if (((leaf_idx ^ info->wots_sign_leaf) & ~3) == 0) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
        wots_sign_index = info->wots_sign_leaf & 3; /* Which of of the 4 */
                                  /* 4 slots do the signatures come from */
    } else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
        wots_sign_index = 0;
    }

    for (j = 0; j < 4; j++) {
        set_keypair_addr( leaf_addr + j*8, leaf_idx + j );
        set_keypair_addr( pk_addr + j*8, leaf_idx + j );
    }

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N) {
        /* Phoenix: Determine W based on chain index */
        uint32_t w;
        if (i < SPX_WOTS_W1_LEN) {
            w = SPX_WOTS_W1;
        } else if (i < SPX_WOTS_LEN1) {
            w = SPX_WOTS_W2;
        } else {
            w = SPX_WOTS_CHECKSUM_W;
        }

        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
            /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        for (j = 0; j < 4; j++) {
            set_chain_addr(leaf_addr + j*8, i);
            set_hash_addr(leaf_addr + j*8, 0);
            set_type(leaf_addr + j*8, SPX_ADDR_TYPE_WOTSPRF);
        }
        prf_addrx4(buffer + 0*wots_offset,
                   buffer + 1*wots_offset,
                   buffer + 2*wots_offset,
                   buffer + 3*wots_offset,
                   ctx, leaf_addr);

        for (j = 0; j < 4; j++) {
            set_type(leaf_addr + j*8, SPX_ADDR_TYPE_WOTS);
        }

        /* Iterate down the WOTS chain */
        for (k=0;; k++) {
            /* Check if one of the values we have needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy( info->wots_sig + i * SPX_N,
                        buffer + wots_sign_index*wots_offset, SPX_N );
            }

            /* Check if we hit the top of the chain */
            if (k == w - 1) break;

            /* Iterate one step on all 4 chains */
            for (j = 0; j < 4; j++) {
                set_hash_addr(leaf_addr + j*8, k);
            }
            thashx4(buffer + 0*wots_offset,
                    buffer + 1*wots_offset,
                    buffer + 2*wots_offset,
                    buffer + 3*wots_offset,
                    buffer + 0*wots_offset,
                    buffer + 1*wots_offset,
                    buffer + 2*wots_offset,
                    buffer + 3*wots_offset, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thashx4(dest + 0*SPX_N,
            dest + 1*SPX_N,
            dest + 2*SPX_N,
            dest + 3*SPX_N,
            pk_buffer + 0*wots_offset,
            pk_buffer + 1*wots_offset,
            pk_buffer + 2*wots_offset,
            pk_buffer + 3*wots_offset, SPX_WOTS_LEN, ctx, pk_addr);
}