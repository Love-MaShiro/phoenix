#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "thash.h"
#include "gwotsc.h"
#include "gwotscx1.h"
#include "address.h"
#include "params.h"

/* Generate GWOTSC public key and optionally signature for specified leaf. */
void gwotsc_gen_leafx1(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info)
{
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int chain_idx, step_idx;
    unsigned char pk_buf[ PH_GWOTSC_BYTES ];
    unsigned char *chain_buf;
    uint32_t gwotsc_k_mask;
    uint32_t gwotsc_k_val;

    /* Determine if signing with this leaf or just generating PK */
    if (leaf_idx == info->gwotsc_sign_leaf) {
        gwotsc_k_mask = 0;
    } else {
        gwotsc_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (chain_idx = 0, chain_buf = pk_buf; chain_idx < PH_GWOTSC_LEN; chain_idx++, chain_buf += PH_N) {
        /* Determine chain length parameter */
        uint32_t chain_w;
        if (chain_idx < PH_GWOTSC_W1_LEN) {
            chain_w = PH_GWOTSC_W1;
        } else if (chain_idx < PH_GWOTSC_LEN1) {
            chain_w = PH_GWOTSC_W2;
        } else {
            chain_w = PH_GWOTSC_CHECKSUM_W;
        }

        gwotsc_k_val = info->gwotsc_steps[chain_idx] | gwotsc_k_mask;

        /* Initialize chain with secret seed */
        set_chain_addr(leaf_addr, chain_idx);
        set_hash_addr(leaf_addr, 0);
        set_addr_type(leaf_addr, PH_ADDR_TYPE_GWOTSCPRF);
        prf_addr(chain_buf, ctx, leaf_addr);

        set_addr_type(leaf_addr, PH_ADDR_TYPE_GWOTSC);

        /* Iterate down the chain */
        for (step_idx = 0; ; step_idx++) {
            /* Save signature value at specified step */
            if (step_idx == gwotsc_k_val) {
                memcpy(info->gwotsc_sig + chain_idx * PH_N, chain_buf, PH_N);
            }

            /* Stop at chain top */
            if (step_idx == chain_w - 1) break;

            set_hash_addr(leaf_addr, step_idx);
            thash(chain_buf, chain_buf, 1, ctx, leaf_addr);
        }
    }

    /* Final compression to generate public keys */
    thash(dest, pk_buf, PH_GWOTSC_LEN, ctx, pk_addr);
}
