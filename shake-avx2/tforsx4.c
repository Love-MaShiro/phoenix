#include <string.h>
#include <stdint.h>

#include "tforsx4.h"
#include "hash.h"
#include "hashx4.h"
#include "thash.h"
#include "thashx4.h"
#include "address.h"
#include "params.h"
#include "context.h"

void tfors_gen_sk_x4(unsigned char *out0,
                     unsigned char *out1,
                     unsigned char *out2,
                     unsigned char *out3,
                     const spx_ctx *ctx,
                     const uint32_t addrx4[4 * 8])
{
    prf_addrx4(out0, out1, out2, out3, ctx, addrx4);
}

void tfors_sk_to_leaf_x4(unsigned char *out0,
                         unsigned char *out1,
                         unsigned char *out2,
                         unsigned char *out3,
                         const unsigned char *in0,
                         const unsigned char *in1,
                         const unsigned char *in2,
                         const unsigned char *in3,
                         const spx_ctx *ctx,
                         uint32_t addrx4[4 * 8])
{
    thashx4(out0, out1, out2, out3, in0, in1, in2, in3, 1, ctx, addrx4);
}

void tfors_precompute_leaves_x4(unsigned char *precomputed,
                                const spx_ctx *ctx,
                                const uint32_t tree_addr[8],
                                const uint8_t *is_target,
                                uint32_t num_leaves)
{
    uint32_t valid_leaf_count = SPX_TFORS_K * (1u << SPX_TFORS_A);
    uint32_t idx = 0;

    /* Process valid non-target leaves in batches of 4 */
    while (idx + 3 < valid_leaf_count) {
        /* Check if all 4 are non-target */
        if (!is_target[idx] && !is_target[idx + 1] &&
            !is_target[idx + 2] && !is_target[idx + 3]) {

            /* Build 4 PRF addresses (type = TFORSPRF) */
            uint32_t prf_addrx4[4 * 8];
            for (int lane = 0; lane < 4; lane++) {
                copy_keypair_addr(&prf_addrx4[lane * 8], tree_addr);
                set_tree_height(&prf_addrx4[lane * 8], 0);
                set_tree_index(&prf_addrx4[lane * 8], idx + lane);
                set_type(&prf_addrx4[lane * 8], SPX_ADDR_TYPE_TFORSPRF);
            }

            /* Batch PRF to get 4 secret keys */
            unsigned char sk0[SPX_N], sk1[SPX_N], sk2[SPX_N], sk3[SPX_N];
            tfors_gen_sk_x4(sk0, sk1, sk2, sk3, ctx, prf_addrx4);

            /* Build 4 THASH addresses (type = TFORSTREE) */
            uint32_t thash_addrx4[4 * 8];
            for (int lane = 0; lane < 4; lane++) {
                copy_keypair_addr(&thash_addrx4[lane * 8], tree_addr);
                set_tree_height(&thash_addrx4[lane * 8], 0);
                set_tree_index(&thash_addrx4[lane * 8], idx + lane);
                set_type(&thash_addrx4[lane * 8], SPX_ADDR_TYPE_TFORSTREE);
            }

            /* Batch THASH to get 4 leaf hashes */
            tfors_sk_to_leaf_x4(
                &precomputed[(idx + 0) * SPX_N],
                &precomputed[(idx + 1) * SPX_N],
                &precomputed[(idx + 2) * SPX_N],
                &precomputed[(idx + 3) * SPX_N],
                sk0, sk1, sk2, sk3,
                ctx, thash_addrx4);

            idx += 4;
        } else {
            /* At least one is a target leaf; handle individually with scalar */
            for (int lane = 0; lane < 4; lane++) {
                uint32_t cur = idx + lane;
                if (!is_target[cur]) {
                    uint32_t leaf_addr[8] = {0};
                    unsigned char sk[SPX_N];

                    copy_keypair_addr(leaf_addr, tree_addr);
                    set_tree_height(leaf_addr, 0);
                    set_tree_index(leaf_addr, cur);
                    set_type(leaf_addr, SPX_ADDR_TYPE_TFORSPRF);
                    prf_addr(sk, ctx, leaf_addr);

                    set_type(leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
                    tfors_sk_to_leaf(&precomputed[cur * SPX_N], sk, ctx, leaf_addr);
                }
                /* Target leaves: caller fills from target_hash */
            }
            idx += 4;
        }
    }

    /* Handle remaining valid leaves (< 4 tail) */
    while (idx < valid_leaf_count) {
        if (!is_target[idx]) {
            uint32_t leaf_addr[8] = {0};
            unsigned char sk[SPX_N];

            copy_keypair_addr(leaf_addr, tree_addr);
            set_tree_height(leaf_addr, 0);
            set_tree_index(leaf_addr, idx);
            set_type(leaf_addr, SPX_ADDR_TYPE_TFORSPRF);
            prf_addr(sk, ctx, leaf_addr);

            set_type(leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
            tfors_sk_to_leaf(&precomputed[idx * SPX_N], sk, ctx, leaf_addr);
        }
        idx++;
    }

    /* Zero-fill padding leaves beyond valid range */
    if (valid_leaf_count < num_leaves) {
        memset(&precomputed[valid_leaf_count * SPX_N], 0,
               (num_leaves - valid_leaf_count) * SPX_N);
    }
}
