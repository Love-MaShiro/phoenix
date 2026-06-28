#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "hashx4.h"
#include "thash.h"
#include "thashx4.h"
#include "gwotsc.h"
#include "gwotscx4.h"
#include "address.h"
#include "params.h"

/* Generate 4 parallel GWOTSC public keys with optional signature. */
void gwotsc_gen_leafx4(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info)
{
    struct leaf_info_x4 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int chain_idx, step_idx, lane_idx;
    unsigned char pk_buf[ 4 * PH_GWOTSC_BYTES ];
    unsigned gwotsc_stride = PH_GWOTSC_BYTES;
    unsigned char *chain_buf;
    uint32_t gwotsc_k_mask;
    unsigned gwotsc_sign_lane;

    /* Determine signing mode and signature lane */
    if (((leaf_idx ^ info->gwotsc_sign_leaf) & ~3) == 0) {
        gwotsc_k_mask = 0;
        gwotsc_sign_lane = info->gwotsc_sign_leaf & 3;
    } else {
        gwotsc_k_mask = (uint32_t)~0;
        gwotsc_sign_lane = 0;
    }

    /* Initialize address registers for 4 lanes */
    for (lane_idx = 0; lane_idx < 4; lane_idx++) {
        set_keypair_addr(leaf_addr + lane_idx*8, leaf_idx + lane_idx);
        set_keypair_addr(pk_addr + lane_idx*8, leaf_idx + lane_idx);
    }

    /* Process each chain position */
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

        uint32_t gwotsc_k_val = info->gwotsc_steps[chain_idx] | gwotsc_k_mask;

        /* Initialize chains with secret seeds */
        for (lane_idx = 0; lane_idx < 4; lane_idx++) {
            set_chain_addr(leaf_addr + lane_idx*8, chain_idx);
            set_hash_addr(leaf_addr + lane_idx*8, 0);
            set_addr_type(leaf_addr + lane_idx*8, PH_ADDR_TYPE_GWOTSCPRF);
        }
        prf_addrx4(chain_buf + 0*gwotsc_stride,
                   chain_buf + 1*gwotsc_stride,
                   chain_buf + 2*gwotsc_stride,
                   chain_buf + 3*gwotsc_stride,
                   ctx, leaf_addr);

        for (lane_idx = 0; lane_idx < 4; lane_idx++) {
            set_addr_type(leaf_addr + lane_idx*8, PH_ADDR_TYPE_GWOTSC);
        }

        /* Iterate down the chain */
        for (step_idx = 0; ; step_idx++) {
            /* Save signature at specified step */
            if (step_idx == gwotsc_k_val) {
                memcpy(info->gwotsc_sig + chain_idx * PH_N,
                       chain_buf + gwotsc_sign_lane*gwotsc_stride, PH_N);
            }

            /* Stop at chain top */
            if (step_idx == chain_w - 1) break;

            /* Parallel thash for all 4 lanes */
            for (lane_idx = 0; lane_idx < 4; lane_idx++) {
                set_hash_addr(leaf_addr + lane_idx*8, step_idx);
            }
            thashx4(chain_buf + 0*gwotsc_stride,
                    chain_buf + 1*gwotsc_stride,
                    chain_buf + 2*gwotsc_stride,
                    chain_buf + 3*gwotsc_stride,
                    chain_buf + 0*gwotsc_stride,
                    chain_buf + 1*gwotsc_stride,
                    chain_buf + 2*gwotsc_stride,
                    chain_buf + 3*gwotsc_stride, 1, ctx, leaf_addr);
        }
    }

    /* Final compression for 4 parallel public keys */
    thashx4(dest + 0*PH_N,
            dest + 1*PH_N,
            dest + 2*PH_N,
            dest + 3*PH_N,
            pk_buf + 0*gwotsc_stride,
            pk_buf + 1*gwotsc_stride,
            pk_buf + 2*gwotsc_stride,
            pk_buf + 3*gwotsc_stride, PH_GWOTSC_LEN, ctx, pk_addr);
}
