#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2*SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    shake256(out, SPX_N, buf, 2*SPX_N + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(s_inc, optrand, SPX_N);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, SPX_N, s_inc);
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

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, SPX_N);
    shake256_inc_absorb(s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);

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
 * Generates k distinct leaf indices from a message digest using PRNG.
 *
 * This function implements the PRNG to Obtain a Random Subset algorithm
 * from the PORS paper. It uses the SPHINCS+ PRF as the underlying
 * pseudorandom function.
 *
 * Returns 0 on success, 1 on failure.
 */
// int h2_generate_indices(uint32_t indices[SPX_TFORS_K],
//                         const unsigned char msg_digest[SPX_N],
//                         const spx_ctx *ctx)
// {
//     printf("h2_generate_indices called with msg_digest: ");
//     for (size_t i = 0; i < SPX_N; i++) {
//         printf("%02x", msg_digest[i]);  
//     }
//     const uint32_t k = SPX_TFORS_K;
//     const uint32_t t = SPX_TFORS_K_PRIME;
//     uint32_t ctr = 0;
//     uint32_t collected = 0;
//     uint64_t used = 0;

//     uint32_t log2_t = 0;
//     uint32_t tmp = t - 1;
//     while (tmp > 0) {
//         log2_t++;
//         tmp >>= 1;
//     }

//     uint32_t addr[8] = {0};
//     set_type(addr, SPX_ADDR_TYPE_H2);

//     while (collected < k) {
//         unsigned char rnd[SPX_N];
//         set_leaf_index(addr, ctr++);
//         prf_addr(rnd, ctx, addr);

//         for (size_t i = 0; i < SPX_N; i++) {
//             rnd[i] ^= msg_digest[i];
//         }

//         uint64_t val = 0;
//         for (size_t i = 0; i < sizeof(uint64_t) && i < SPX_N; i++) {
//             val = (val << 8) | rnd[i];
//         }

//         uint32_t idx = val & ((1 << log2_t) - 1);
//         if (idx >= t) continue;

//         uint64_t mask = 1ULL << idx;
//         if (!(used & mask)) {
//             used |= mask;
//             indices[collected++] = idx;
//         }

//         if (ctr > 10000) return -1;
//     }

//     for (uint32_t i = 0; i < k; i++) {
//         for (uint32_t j = i + 1; j < k; j++) {
//             if (indices[i] > indices[j]) {
//                 uint32_t temp = indices[i];
//                 indices[i] = indices[j];
//                 indices[j] = temp;
//             }
//         }
//     }

//     return 0;
// }
/**
 * Generates k distinct leaf indices from a message digest using PRNG.
 *
 * This function uses only the public seed and message digest, so it works
 * identically for both signing and verification.
 */
int h2_generate_indices(uint32_t indices[SPX_TFORS_K],
                        const unsigned char msg_digest[SPX_N],
                        const spx_ctx *ctx)
{
    printf("shake shixian h2");
    const uint32_t k = SPX_TFORS_K;
    const uint32_t t = SPX_TFORS_T;
    uint32_t log2_t = 0;
    uint32_t tmp = t - 1;
    while (tmp > 0) {
        log2_t++;
        tmp >>= 1;
    }

    // ================================
    // ✅ 正确：把 msg_digest + pub_seed 一起哈希！
    // ================================
    unsigned char input[SPX_N + SPX_N];
    memcpy(input, msg_digest, SPX_N);
    memcpy(input + SPX_N, ctx->pub_seed, SPX_N);  // 👈 把 ctx 加进来

    unsigned char rnd[512];
    shake256(rnd, sizeof(rnd), input, sizeof(input));  // 👈 一起输入
    size_t rnd_ptr = 0;

    uint8_t mask[t / 8] = {0};
    uint32_t count = 0;

    if (k <= t / 2) {
        while (count < k) {
            if (rnd_ptr + 8 > sizeof(rnd)) return -1;
            uint64_t val = 0;
            for (int i = 0; i < 8; i++) {
                val = (val << 8) | rnd[rnd_ptr++];
            }
            uint32_t idx = val & ((1U << log2_t) - 1);
            if (idx >= t) continue;
            if (!(mask[idx / 8] & (1 << (idx % 8)))) {
                mask[idx / 8] |= (1 << (idx % 8));
                indices[count++] = idx;
            }
        }
    } else {
        uint8_t reject_mask[t / 8] = {0};
        uint32_t reject_need = t - k;
        count = 0;
        while (count < reject_need) {
            if (rnd_ptr + 8 > sizeof(rnd)) return -1;
            uint64_t val = 0;
            for (int i = 0; i < 8; i++) {
                val = (val << 8) | rnd[rnd_ptr++];
            }
            uint32_t idx = val & ((1U << log2_t) - 1);
            if (idx >= t) continue;
            if (!(reject_mask[idx / 8] & (1 << (idx % 8)))) {
                reject_mask[idx / 8] |= (1 << (idx % 8));
                count++;
            }
        }
        count = 0;
        for (uint32_t i = 0; i < t && count < k; i++) {
            if (!(reject_mask[i / 8] & (1 << (i % 8)))) {
                indices[count++] = i;
            }
        }
    }

    // 排序
    for (uint32_t i = 0; i < k; i++) {
        for (uint32_t j = i + 1; j < k; j++) {
            if (indices[i] > indices[j]) {
                uint32_t temp = indices[i];
                indices[i] = indices[j];
                indices[j] = temp;
            }
        }
    }

    return 0;
}