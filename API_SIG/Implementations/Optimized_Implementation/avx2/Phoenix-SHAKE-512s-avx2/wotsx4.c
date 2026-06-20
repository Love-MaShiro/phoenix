#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx4.h"
#include "hashx4.h"
#include "thashx4.h"
#include "wots.h"
#include "wotsx4.h"
#include "address.h"
#include "params.h"

void wots_gen_leafx4(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x4 *info = v_info;
    unsigned char pk0[SPX_WOTS_BYTES];
    unsigned char pk1[SPX_WOTS_BYTES];
    unsigned char pk2[SPX_WOTS_BYTES];
    unsigned char pk3[SPX_WOTS_BYTES];
    unsigned char chain0[SPX_N];
    unsigned char chain1[SPX_N];
    unsigned char chain2[SPX_N];
    unsigned char chain3[SPX_N];
    uint32_t wots_k_mask[4];

    for (uint32_t lane = 0; lane < 4; lane++) {
        uint32_t lane_leaf = leaf_idx + lane;
        uint32_t *leaf_addr = info->leaf_addr + lane * 8;
        uint32_t *pk_addr = info->pk_addr + lane * 8;

        if (lane_leaf == info->wots_sign_leaf) {
            wots_k_mask[lane] = 0;
        } else {
            wots_k_mask[lane] = ~0u;
        }
        set_keypair_addr(leaf_addr, lane_leaf);
        set_keypair_addr(pk_addr, lane_leaf);
    }

    for (uint32_t i = 0; i < SPX_WOTS_LEN; i++) {
        unsigned int starts[4] = {0, 0, 0, 0};
        unsigned int full_steps[4];
        unsigned int sig_steps[4] = {0, 0, 0, 0};
        unsigned char sig0[SPX_N];
        unsigned char sig1[SPX_N];
        unsigned char sig2[SPX_N];
        unsigned char sig3[SPX_N];
        uint32_t w;
        int have_sig_lane = 0;

        if (i < SPX_WOTS_W1_LEN) {
            w = SPX_WOTS_W1;
        } else if (i < SPX_WOTS_LEN1) {
            w = SPX_WOTS_W2;
        } else {
            w = SPX_WOTS_CHECKSUM_W;
        }

        for (uint32_t lane = 0; lane < 4; lane++) {
            uint32_t *leaf_addr = info->leaf_addr + lane * 8;
            full_steps[lane] = w - 1;
            set_chain_addr(leaf_addr, i);
            set_hash_addr(leaf_addr, 0);
            set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

            if (wots_k_mask[lane] == 0u && info->wots_sig != 0) {
                sig_steps[lane] = info->wots_steps[i];
                have_sig_lane = 1;
            }
        }

        prf_addrx4(chain0, chain1, chain2, chain3, ctx, info->leaf_addr);

        for (uint32_t lane = 0; lane < 4; lane++) {
            set_type(info->leaf_addr + lane * 8, SPX_ADDR_TYPE_WOTS);
        }

        if (have_sig_lane) {
            chainx4(sig0, sig1, sig2, sig3,
                    chain0, chain1, chain2, chain3,
                    starts, sig_steps, ctx, info->leaf_addr, w);

            for (uint32_t lane = 0; lane < 4; lane++) {
                if (wots_k_mask[lane] == 0u && info->wots_sig != 0) {
                    const unsigned char *sig_src;

                    if (lane == 0) {
                        sig_src = sig0;
                    } else if (lane == 1) {
                        sig_src = sig1;
                    } else if (lane == 2) {
                        sig_src = sig2;
                    } else {
                        sig_src = sig3;
                    }

                    memcpy(info->wots_sig + i * SPX_N, sig_src, SPX_N);
                }
            }
        }

        chainx4(chain0, chain1, chain2, chain3,
                chain0, chain1, chain2, chain3,
                starts, full_steps, ctx, info->leaf_addr, w);

        memcpy(pk0 + i * SPX_N, chain0, SPX_N);
        memcpy(pk1 + i * SPX_N, chain1, SPX_N);
        memcpy(pk2 + i * SPX_N, chain2, SPX_N);
        memcpy(pk3 + i * SPX_N, chain3, SPX_N);
    }

    thashx4(dest + 0 * SPX_N,
            dest + 1 * SPX_N,
            dest + 2 * SPX_N,
            dest + 3 * SPX_N,
            pk0, pk1, pk2, pk3,
            SPX_WOTS_LEN, ctx, info->pk_addr);
}