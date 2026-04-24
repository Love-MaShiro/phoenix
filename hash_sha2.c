#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "sha2.h"

#if SPX_N >= 24
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA512_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA512_BLOCK_BYTES
#define shaX_inc_init sha512_inc_init
#define shaX_inc_blocks sha512_inc_blocks
#define shaX_inc_finalize sha512_inc_finalize
#define shaX sha512
#define mgf1_X mgf1_512
#else
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA256_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA256_BLOCK_BYTES
#define shaX_inc_init sha256_inc_init
#define shaX_inc_blocks sha256_inc_blocks
#define shaX_inc_finalize sha256_inc_finalize
#define shaX sha256
#define mgf1_X mgf1_256
#endif


/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx)
{
    seed_state(ctx);
}

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
#ifdef SPX_SHA512
    uint8_t sha2_state[72];
    unsigned char buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    /* Remainder: ADDR^c ‖ SK.seed */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sha512_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);
#else
    uint8_t sha2_state[40];
    unsigned char buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    /* Remainder: ADDR^c ‖ SK.seed */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);
#endif

    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least SPX_SHAX_BLOCK_BYTES + SPX_N space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;

    unsigned char buf[SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
    uint8_t state[8 + SPX_SHAX_OUTPUT_BYTES];
    int i;

#if SPX_N > SPX_SHAX_BLOCK_BYTES
    #error "Currently only supports SPX_N of at most SPX_SHAX_BLOCK_BYTES"
#endif

    /* This implements HMAC-SHA */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX_inc_init(state);
    shaX_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, SPX_N);

    /* If optrand + message cannot fill up an entire block */
    if (SPX_N + mlen < SPX_SHAX_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, mlen);
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, state,
                            buf, mlen + SPX_N);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(buf + SPX_N, m, SPX_SHAX_BLOCK_BYTES - SPX_N);
        shaX_inc_blocks(state, buf, 1);

        m += SPX_SHAX_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHAX_BLOCK_BYTES - SPX_N;
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, state, m, mlen);
    }

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX(buf, buf, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_TFORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char seed[2*SPX_N + SPX_SHAX_OUTPUT_BYTES];

    /* Round to nearest multiple of SPX_SHAX_BLOCK_BYTES */
#if (SPX_SHAX_BLOCK_BYTES & (SPX_SHAX_BLOCK_BYTES-1)) != 0
    #error "Assumes that SPX_SHAX_BLOCK_BYTES is a power of 2"
#endif
#define SPX_INBLOCKS (((SPX_N + SPX_PK_BYTES + SPX_SHAX_BLOCK_BYTES - 1) & \
                        -SPX_SHAX_BLOCK_BYTES) / SPX_SHAX_BLOCK_BYTES)
    unsigned char inbuf[SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t state[8 + SPX_SHAX_OUTPUT_BYTES];

    shaX_inc_init(state);

    // seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    /* If R + pk + message cannot fill up an entire block */
    if (SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
        shaX_inc_finalize(seed + 2*SPX_N, state, inbuf, SPX_N + SPX_PK_BYTES + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m,
               SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES);
        shaX_inc_blocks(state, inbuf, SPX_INBLOCKS);

        m += SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        mlen -= SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        shaX_inc_finalize(seed + 2*SPX_N, state, m, mlen);
    }

    // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, SPX_N);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1_X(bufp, SPX_DGST_BYTES, seed, 2*SPX_N + SPX_SHAX_OUTPUT_BYTES);

    memcpy(digest, bufp, SPX_TFORS_MSG_BYTES);
    bufp += SPX_TFORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1) {
	*tree = 0;
    } else {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}

/**
 * H₂ function: Generates k distinct key-set indices.
 * 
 * This function uses SHA2 as a deterministic PRNG. The same msg_digest
 * input will always produce the same output indices, which is essential
 * for signature verification.
 * 
 * Parameters:
 *   indices      - Output array of k distinct indices
 *   msg_digest   - Message digest (n bytes) from hash_message
 *   ctx          - SPHINCS+ context (for Haraka)
 * 
 * Returns 0 on success, 1 on failure.
 */
// int h2_generate_indices(uint32_t *indices,
//                                const unsigned char *msg_digest,
//                                const spx_ctx *ctx)
// {
//     (void)ctx;
//     printf("h2_generate_indices called with msg_digest: ");
//     for (size_t i = 0; i < SPX_N; i++) {
//         printf("%02x", msg_digest[i]);
//     }
    
//     const uint32_t k_prime = SPX_TFORS_K_PRIME;
//     const uint32_t k = SPX_TFORS_K;
//     const size_t n = SPX_N;
//     const uint32_t log2_kp = SPX_TFORS_LOG_K_PRIME;  /* Compile-time constant */
    
//     /* Determine strategy: generate smaller set */
//     const uint32_t m = (k <= k_prime / 2) ? k : (k_prime - k);
//     const int use_complement = (k > k_prime / 2);
    
//     uint32_t temp_indices[SPX_TFORS_K_PRIME];
//     uint32_t collected = 0;
//     uint64_t used_mask = 0;
       
//     unsigned char h2_input[SPX_N];
//     memcpy(h2_input, msg_digest, n);
    
//     /* Hash the input */
//     unsigned char hash_out[SPX_SHAX_OUTPUT_BYTES];
//     shaX(hash_out, h2_input, SPX_N + 4);
    
//     /* Number of indices per hash output */
//     uint32_t per_block = (SPX_SHAX_OUTPUT_BYTES * 8) / log2_kp;
//     if (per_block == 0) per_block = 1;
    
//     /* Extract indices from hash output */
//     uint64_t val = 0;
//     size_t bytes = (SPX_SHAX_OUTPUT_BYTES < sizeof(uint64_t))
//                    ? SPX_SHAX_OUTPUT_BYTES
//                    : sizeof(uint64_t);
//     for (size_t i = 0; i < bytes; i++) {
//         val = (val << 8) | hash_out[i];
//     }
    
//     for (uint32_t i = 0; i < per_block && collected < m; i++) {
//         uint32_t shift = (per_block - 1 - i) * log2_kp;
//         uint32_t idx = (val >> shift) & ((1 << log2_kp) - 1);
        
//         uint64_t mask = 1ULL << idx;
//         if (!(used_mask & mask)) {
//             used_mask |= mask;
//             temp_indices[collected++] = idx;
//         }
//     }
    
//     /* Chain hash if more indices needed */
//     unsigned char prev[SPX_SHAX_OUTPUT_BYTES];
//     memcpy(prev, hash_out, SPX_SHAX_OUTPUT_BYTES);
    
//     while (collected < m) {
//         shaX(hash_out, prev, SPX_SHAX_OUTPUT_BYTES);
//         memcpy(prev, hash_out, SPX_SHAX_OUTPUT_BYTES);
        
//         val = 0;
//         for (size_t i = 0; i < bytes; i++) {
//             val = (val << 8) | hash_out[i];
//         }
        
//         for (uint32_t i = 0; i < per_block && collected < m; i++) {
//             uint32_t shift = (per_block - 1 - i) * log2_kp;
//             uint32_t idx = (val >> shift) & ((1 << log2_kp) - 1);
            
//             uint64_t mask = 1ULL << idx;
//             if (!(used_mask & mask)) {
//                 used_mask |= mask;
//                 temp_indices[collected++] = idx;
//             }
//         }
//     }
    
//     /* Convert to final output */
//     if (!use_complement) {
//         /* Direct case: need to sort temp_indices */
//         for (uint32_t i = 1; i < k; i++) {
//             uint32_t key = temp_indices[i];
//             int32_t j = (int32_t)i - 1;
//             while (j >= 0 && temp_indices[j] > key) {
//                 temp_indices[j + 1] = temp_indices[j];
//                 j--;
//             }
//             temp_indices[j + 1] = key;
//         }
//         memcpy(indices, temp_indices, k * sizeof(uint32_t));
//     } else {
//         /* Complement case: natural order, no sorting needed */
//         uint32_t complement_idx = 0;
//         uint64_t exclude_mask = used_mask;
        
//         for (uint32_t i = 0; i < k_prime; i++) {
//             if (!(exclude_mask & (1ULL << i))) {
//                 indices[complement_idx++] = i;
//             }
//         }
//     }
    
//     return 0;
// }

/**
 * H₂ function: Generates k distinct key-set indices.
 * 
 * This function uses SHA2 as a deterministic PRNG. The same msg_digest
 * input will always produce the same output indices, which is essential
 * for signature verification.
 */
int h2_generate_indices(uint32_t *indices,
                        const unsigned char *msg_digest,
                        const spx_ctx *ctx)
{
    const uint32_t k = SPX_TFORS_K;
    const uint32_t k_prime = SPX_TFORS_K_PRIME;
    const uint32_t log2_kp = SPX_TFORS_LOG_K_PRIME;

    SPX_VLA(uint8_t, mask, (k_prime + 7) / 8);
    memset(mask, 0, (k_prime + 7) / 8);
    uint32_t count = 0;

    // ==============================================
    // ✅ 关键修改：把 消息摘要 + pub_seed 一起哈希
    // ==============================================
    unsigned char hash_input[SPX_N + SPX_N];
    memcpy(hash_input, msg_digest, SPX_N);          // 消息摘要
    memcpy(hash_input + SPX_N, ctx->pub_seed, SPX_N); // 公钥种子（ctx）

    // 用合并后的数据生成随机流
    unsigned char rnd[512];
#ifdef SPX_SHA512
    mgf1_512(rnd, sizeof(rnd), hash_input, sizeof(hash_input));
#else
    mgf1_256(rnd, sizeof(rnd), hash_input, sizeof(hash_input));
#endif
    size_t rnd_ptr = 0;

    // ================================
    // 保留你完美的双分支逻辑
    // ================================
    if (k <= k_prime / 2) {
        // 情况 A：少选 → 随机选 k 个
        while (count < k) {
            if (rnd_ptr + 8 > sizeof(rnd)) return -1;

            uint64_t val = 0;
            for (int i = 0; i < 8; i++) val = (val << 8) | rnd[rnd_ptr++];
            uint32_t idx = val & ((1U << log2_kp) - 1);
            if (idx >= k_prime) continue;

            if (!(mask[idx / 8] & (1 << (idx % 8)))) {
                mask[idx / 8] |= (uint8_t)(1 << (idx % 8));
                indices[count++] = idx;
            }
        }
    } else {
        // 情况 B：多选 → 反选丢弃（你要的高效逻辑）
        SPX_VLA(uint8_t, reject_mask, (k_prime + 7) / 8);
        memset(reject_mask, 0, (k_prime + 7) / 8);
        uint32_t reject_num = k_prime - k;
        count = 0;

        while (count < reject_num) {
            if (rnd_ptr + 8 > sizeof(rnd)) return -1;

            uint64_t val = 0;
            for (int i = 0; i < 8; i++) val = (val << 8) | rnd[rnd_ptr++];
            uint32_t idx = val & ((1U << log2_kp) - 1);
            if (idx >= k_prime) continue;

            if (!(reject_mask[idx / 8] & (1 << (idx % 8)))) {
                reject_mask[idx / 8] |= (uint8_t)(1 << (idx % 8));
                count++;
            }
        }

        // 把未丢弃的按顺序放入 indices
        count = 0;
        for (uint32_t i = 0; i < k_prime && count < k; i++) {
            if (!(reject_mask[i / 8] & (1 << (i % 8)))) {
                indices[count++] = i;
            }
        }
    }

    // 稳定排序（必须）
    for (uint32_t i = 0; i < k; i++) {
        for (uint32_t j = i + 1; j < k; j++) {
            if (indices[i] > indices[j]) {
                uint32_t tmp = indices[i];
                indices[i] = indices[j];
                indices[j] = tmp;
            }
        }
    }

    return 0;
}