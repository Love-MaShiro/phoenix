#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "haraka.h"
#include "fips202.h"

#define SPX_HARAKA_OUTPUT_BYTES 32

void initialize_hash_function(spx_ctx* ctx)
{
    tweak_constants(ctx);
}

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    /* Since SPX_N may be smaller than 32, we need temporary buffers. */
    unsigned char outbuf[32];
    unsigned char buf[64] = {0};

    memcpy(buf, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    haraka512(outbuf, (const void *)buf, ctx);
    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char* sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, sk_prf, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, optrand, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, m, mlen, ctx);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(R, SPX_N, s_inc, ctx);
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
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_TFORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, R, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, pk + SPX_N, SPX_N, ctx); // Only absorb root part of pk
    haraka_S_inc_absorb(s_inc, m, mlen, ctx);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(buf, SPX_DGST_BYTES, s_inc, ctx);

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


int h2_generate_indices(uint32_t *indices,
                        const unsigned char *msg_digest,
                        const spx_ctx *ctx)
{
    (void)ctx;
    
    const uint32_t k_prime = SPX_TFORS_K_PRIME;
    const uint32_t k = SPX_TFORS_K;
    const uint32_t log2_kp = SPX_TFORS_LOG_K_PRIME;
    
    const uint32_t m = (k <= k_prime / 2) ? k : (k_prime - k);
    const int use_complement = (k > k_prime / 2);
    
    uint32_t temp_indices[SPX_TFORS_K_PRIME];
    uint32_t collected = 0;
    uint64_t used_mask = 0;
    
    // 使用 SPX_N 的倍数作为输出大小，SHAKE256 可以产生任意长度
    unsigned char hash_out[SPX_N * 2];  // 32 或 64 字节
    uint64_t s_inc[26];
    
    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, msg_digest, SPX_N);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(hash_out, SPX_N * 2, s_inc);
    
    uint32_t per_block = (SPX_N * 2 * 8) / log2_kp;
    if (per_block == 0) per_block = 1;
    
    uint64_t val = 0;
    size_t bytes = (SPX_N * 2 < sizeof(uint64_t)) ? SPX_N * 2 : sizeof(uint64_t);
    for (size_t i = 0; i < bytes; i++) {
        val = (val << 8) | hash_out[i];
    }
    
    for (uint32_t i = 0; i < per_block && collected < m; i++) {
        uint32_t shift = (per_block - 1 - i) * log2_kp;
        uint32_t idx = (uint32_t)((val >> shift) & ((1ULL << log2_kp) - 1));
        
        uint64_t mask = 1ULL << idx;
        if (!(used_mask & mask)) {
            used_mask |= mask;
            temp_indices[collected++] = idx;
        }
    }
    
    /* Chain hash if more indices needed */
    unsigned char prev[SPX_N * 2];
    memcpy(prev, hash_out, SPX_N * 2);
    
    while (collected < m) {
        shake256(hash_out, SPX_N * 2, prev, SPX_N * 2);
        memcpy(prev, hash_out, SPX_N * 2);
        
        val = 0;
        for (size_t i = 0; i < bytes; i++) {
            val = (val << 8) | hash_out[i];
        }
        
        for (uint32_t i = 0; i < per_block && collected < m; i++) {
            uint32_t shift = (per_block - 1 - i) * log2_kp;
            uint32_t idx = (uint32_t)((val >> shift) & ((1ULL << log2_kp) - 1));
            
            uint64_t mask = 1ULL << idx;
            if (!(used_mask & mask)) {
                used_mask |= mask;
                temp_indices[collected++] = idx;
            }
        }
    }
    
    /* Convert to final output */
    if (!use_complement) {
        for (uint32_t i = 1; i < k; i++) {
            uint32_t key = temp_indices[i];
            int32_t j = (int32_t)i - 1;
            while (j >= 0 && temp_indices[j] > key) {
                temp_indices[j + 1] = temp_indices[j];
                j--;
            }
            temp_indices[j + 1] = key;
        }
        memcpy(indices, temp_indices, k * sizeof(uint32_t));
    } else {
        uint32_t complement_idx = 0;
        uint64_t exclude_mask = used_mask;
        
        for (uint32_t i = 0; i < k_prime; i++) {
            if (!(exclude_mask & (1ULL << i))) {
                indices[complement_idx++] = i;
            }
        }
    }
    
    return 0;
}