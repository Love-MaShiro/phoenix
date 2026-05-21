#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "tfors.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "octopus.h"

// 打印uint32_t[8]类型的SPX地址
static void print_spx_addr(const char *name, const uint32_t addr[8])
{
    printf("=== %s ===\n", name);
    for (int i = 0; i < 8; i++) {
        // 十六进制打印（8位宽度，补0），同时打印十进制（可选）
        printf("addr[%d] = 0x%08x (dec: %u)\n", i, addr[i], addr[i]);
    }
    printf("===========\n\n");
}

static void tfors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t tfors_leaf_addr[8])
{
    prf_addr(sk, ctx, tfors_leaf_addr);
}

void tfors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t tfors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, tfors_leaf_addr);
}

struct tfors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};


static void sort_indices(uint32_t *indices)
{
    for (uint32_t i = 1; i < SPX_TFORS_K; i++) {
        uint32_t key = indices[i];
        int j = i - 1;
        while (j >= 0 && indices[j] > key) {
            indices[j + 1] = indices[j];
            j--;
        }
        indices[j + 1] = key;
    }
}

/**
 * Generates TFORS leaf indices from a message.
 * First uses H2 to generate indices1 in [0, SPX_TFORS_K_PRIME-1] from the
 * first SPX_N bytes of the message.
 * Then extracts indices2 in [0, 2^SPX_TFORS_A -1] from the full message bitstream.
 * Final leaf index: indices[i] = indices1[i] + SPX_TFORS_K_PRIME * indices2[i].
 *
 * Assumes m has length at least max(8*SPX_N, SPX_TFORS_A * SPX_TFORS_K) bits.
 * Assumes indices has space for SPX_TFORS_K integers.
 */
void message_to_indices(uint32_t *indices, const unsigned char *m, const spx_ctx *ctx) {
    uint32_t indices1[SPX_TFORS_K];
    uint32_t indices2[SPX_TFORS_K];
    unsigned int i, j;
    
    /* Derive indices1 using H2 from first SPX_N bytes of message */
    h2_generate_indices(indices1, m, ctx);
    
    /* Extract indices2 from the remaining bits (after SPX_N bytes) */
    unsigned int start_bit = SPX_N * 8;
    unsigned int bit_offset = start_bit;
    
    for (i = 0; i < SPX_TFORS_K; i++) {
        indices2[i] = 0;
        for (j = 0; j < SPX_TFORS_A; j++) {
            unsigned int byte_pos = bit_offset >> 3;
            unsigned int bit_in_byte = bit_offset & 0x7;
            
            // indices2[i] ^= ((m[byte_pos] >> bit_in_byte) & 1u) << (unsigned int)j;
            indices2[i] |= ((m[byte_pos] >> bit_in_byte) & 1u) << (unsigned int)j;

            bit_offset++;
        }
    }

    /* Compute final leaf indices from combined indices */
    for (i = 0; i < SPX_TFORS_K; i++) {
        indices[i] = indices1[i] + SPX_TFORS_K_PRIME * indices2[i];
    }

    sort_indices(indices);
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least MAX{8*SPX_N, SPX_TFORS_A * SPX_TFORS_K} bits.
 */
void tfors_sign(unsigned char *sig, unsigned char *pk,
               const uint32_t *indices,
               const spx_ctx *ctx,
               const uint32_t tfors_addr[8])
{
    uint32_t indices_tmp[SPX_TFORS_K];
    octopus_auth_with_hash auth;
    uint32_t tfors_tree_addr[8] = {0};
    struct tfors_gen_leaf_info fors_info = {0};
    uint32_t *tfors_leaf_addr = fors_info.leaf_addrx;
    unsigned char leaf_sk[SPX_TFORS_K][SPX_N];
    unsigned int i;

    memcpy(indices_tmp, indices, SPX_TFORS_K * sizeof(uint32_t));

    copy_keypair_addr(tfors_tree_addr, tfors_addr);
    copy_keypair_addr(tfors_leaf_addr, tfors_addr);

    // 生成叶子私钥
    for (i = 0; i < SPX_TFORS_K; i++) {
        set_tree_height(tfors_tree_addr, 0);
        set_tree_index(tfors_tree_addr, indices_tmp[i]);
        set_type(tfors_tree_addr, SPX_ADDR_TYPE_TFORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        tfors_gen_sk(sig, ctx, tfors_tree_addr);
        set_type(tfors_tree_addr, SPX_ADDR_TYPE_TFORSTREE);
        memcpy(leaf_sk[i], sig, SPX_N);
        sig += SPX_N;
    }
    
    // 计算认证路径
    octopus_compute_auth_paths(pk, &auth, indices_tmp, SPX_TFORS_K, leaf_sk, ctx, tfors_tree_addr);

    // 写入认证路径
    for (uint32_t i = 0; i < auth.count; i++) {
        memcpy(sig, auth.entries[i].hash, SPX_N);
        sig += SPX_N;
    }
}

void tfors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t tfors_addr[8])
{
    uint32_t indices[SPX_TFORS_K];
    octopus_auth_with_hash auth;
    unsigned char leaf[SPX_TFORS_K][SPX_N];
    uint32_t tfors_tree_addr[8] = {0};
    unsigned int i;

    // memcpy(ctx->pub_seed, pk, SPX_N);

    copy_keypair_addr(tfors_tree_addr, tfors_addr);

    set_type(tfors_tree_addr, SPX_ADDR_TYPE_TFORSTREE);

    message_to_indices(indices, m, ctx);

    // 恢复叶子哈希
    for ( i = 0; i < SPX_TFORS_K; i++) {
        uint32_t tfors_leaf_addr[8] = {0};
        copy_keypair_addr(tfors_leaf_addr, tfors_addr);
        set_type(tfors_leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
        set_tree_height(tfors_leaf_addr, 0);
        set_tree_index(tfors_leaf_addr, indices[i]);
        // print_spx_addr("fors_leaf_addr (initial)", tfors_leaf_addr);
        
        tfors_sk_to_leaf(leaf[i], sig, ctx, tfors_leaf_addr);

        sig += SPX_N;
    }

    // 读取认证路径
    octopus_auth auth_indices;
    octopus_compute(&auth_indices, indices);
    auth.count = auth_indices.count;
    
    for (uint32_t i = 0; i < auth.count; i++) {
        auth.entries[i].level = auth_indices.entries[i].level;
        auth.entries[i].index = auth_indices.entries[i].index;
        memcpy(auth.entries[i].hash, sig, SPX_N);
        sig += SPX_N;
    }

    // 重建根
    octopus_recompute_root(pk, indices, SPX_TFORS_K, &auth,
                          (const unsigned char*)leaf,
                          ctx, tfors_tree_addr);
}
