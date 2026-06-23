#ifndef SPX_TFORSX4_H
#define SPX_TFORSX4_H

#include <stdint.h>

#include "params.h"
#include "context.h"

/**
 * Precompute all leaf hashes for TFORS using x4 parallelism.
 * 
 * Phase 1 of the two-phase split: computes prf_addr + tfors_sk_to_leaf
 * for every valid non-target leaf in batches of 4.
 * Target leaves are skipped (caller fills them from target_hash).
 * Padding leaves (idx >= K * 2^A) are zeroed.
 *
 * @param precomputed  Output array of size (num_leaves * SPX_N)
 * @param ctx          SPHINCS+ context (contains sk_seed for prf_addr)
 * @param tree_addr    Base TFORS tree address (keypair part will be copied)
 * @param is_target    Boolean array of size num_leaves; 1 = skip prf
 * @param num_leaves   Total number of leaves = 2^SPX_TFORS_HEIGHT
 */
#define tfors_precompute_leaves_x4 SPX_NAMESPACE(tfors_precompute_leaves_x4)
void tfors_precompute_leaves_x4(unsigned char *precomputed,
                                const spx_ctx *ctx,
                                const uint32_t tree_addr[8],
                                const uint8_t *is_target,
                                uint32_t num_leaves);

/**
 * Batch generate 4 TFORS leaf secret keys using prf_addrx4.
 */
#define tfors_gen_sk_x4 SPX_NAMESPACE(tfors_gen_sk_x4)
void tfors_gen_sk_x4(unsigned char *out0,
                     unsigned char *out1,
                     unsigned char *out2,
                     unsigned char *out3,
                     const spx_ctx *ctx,
                     const uint32_t addrx4[4 * 8]);

/**
 * Batch compute 4 TFORS leaf hashes using thashx4.
 */
#define tfors_sk_to_leaf_x4 SPX_NAMESPACE(tfors_sk_to_leaf_x4)
void tfors_sk_to_leaf_x4(unsigned char *out0,
                         unsigned char *out1,
                         unsigned char *out2,
                         unsigned char *out3,
                         const unsigned char *in0,
                         const unsigned char *in1,
                         const unsigned char *in2,
                         const unsigned char *in3,
                         const spx_ctx *ctx,
                         uint32_t addrx4[4 * 8]);

#endif
