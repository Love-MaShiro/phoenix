#include "octopus.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "context.h"
#include "address.h"
#include "thash.h"
#include "utils.h"
#include "tfors.h"

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

// 比较函数：用于排序
int cmp_uint32(const void *a, const void *b) {
    const uint32_t *pa = (const uint32_t *)a;
    const uint32_t *pb = (const uint32_t *)b;
    return (*pa > *pb) - (*pa < *pb);
}

// 去重函数
uint32_t unique_uint32(uint32_t *arr, uint32_t len) {
    uint32_t write_idx = 1;
    if (len == 0) return 0;
    
    for (uint32_t i = 1; i < len; i++) {
        if (arr[i] != arr[i-1]) {
            arr[write_idx++] = arr[i];
        }
    }
    return write_idx;
}

void octopus_compute_auth_count(const uint32_t *indices, uint32_t len, uint32_t *auth_count) {
    uint32_t current[SPX_TFORS_K];
    uint32_t parent[SPX_TFORS_K];
    uint32_t current_len = len, parent_len = 0;
    uint32_t count = 0;

    memcpy(current, indices, len * sizeof(uint32_t));

    for (uint32_t level = 0; level < SPX_TFORS_HEIGHT; level++) {
        uint32_t i = 0;
        parent_len = 0;

        while (i < current_len) {
            uint32_t idx = current[i];
            uint32_t sibling = idx ^ 1;

            if (i + 1 < current_len && current[i + 1] == sibling) {
                i += 2;
            } else {
                count++;
                i += 1;
            }
            parent[parent_len++] = idx / 2;
        }

        if (parent_len == 0) break;
        qsort(parent, parent_len, sizeof(uint32_t), cmp_uint32);
        current_len = unique_uint32(parent, parent_len);
        memcpy(current, parent, current_len * sizeof(uint32_t));
    }
    *auth_count = count;
}

// 计算父节点哈希
static void compute_parent_hash(unsigned char *parent_hash,
                                const unsigned char *left_hash,
                                const unsigned char *right_hash,
                                uint32_t parent_idx,
                                uint32_t height,
                                const spx_ctx *ctx,
                                uint32_t tree_addr[8])
{
    uint32_t node_addr[8];
    unsigned char combined[2 * SPX_N];

    copy_keypair_addr(node_addr, tree_addr);
    set_tree_height(node_addr, height);
    set_tree_index(node_addr, parent_idx);
    set_type(node_addr, SPX_ADDR_TYPE_TFORSTREE);

    memcpy(combined, left_hash, SPX_N);
    memcpy(combined + SPX_N, right_hash, SPX_N);
    
    thash(parent_hash, combined, 2, ctx, node_addr);
}

void octopus_compute(octopus_auth *auth,
                     const uint32_t *indices)
{
    uint32_t current_indices[SPX_TFORS_K];
    uint32_t parent_indices[SPX_TFORS_K];
    uint32_t current_len = SPX_TFORS_K;
    uint32_t tfors_height = SPX_TFORS_HEIGHT;
    
    // 复制并排序输入索引
    memcpy(current_indices, indices, SPX_TFORS_K * sizeof(uint32_t));
    qsort(current_indices, current_len, sizeof(uint32_t), cmp_uint32);
    current_len = unique_uint32(current_indices, current_len);
    
    auth->count = 0;
    
    // 从叶子层向上处理
    for (uint32_t level = 0; level < tfors_height; level++) {
        uint32_t parent_len = 0;
        uint32_t i = 0;
        
        while (i < current_len) {
            uint32_t node_idx = current_indices[i];
            uint32_t parent_idx = node_idx / 2;
            uint32_t sibling_idx = node_idx ^ 1;
            
            // 添加父节点
            parent_indices[parent_len++] = parent_idx;
            
            // 检查兄弟节点是否在当前层中
            if (i + 1 < current_len && current_indices[i + 1] == sibling_idx) {
                i += 2;
            } else {
                if (level < tfors_height - 1) {
                    auth->entries[auth->count].level = level;
                    auth->entries[auth->count].index = sibling_idx;
                    auth->count++;
                }
                i += 1;
            }
        }
        
        if (level == tfors_height - 1) {
            break;
        }
        
        if (parent_len > 0) {
            qsort(parent_indices, parent_len, sizeof(uint32_t), cmp_uint32);
            parent_len = unique_uint32(parent_indices, parent_len);
            memcpy(current_indices, parent_indices, parent_len * sizeof(uint32_t));
            current_len = parent_len;
        } else {
            current_len = 0;
            break;
        }
    }
}   

void octopus_compute_auth_paths(unsigned char root[SPX_N],
                                octopus_auth_with_hash *auth,
                                const uint32_t *indices,
                                uint32_t leaf_count,
                                const unsigned char leaf_sk[][SPX_N],
                                const spx_ctx *ctx,
                                uint32_t tree_addr[8])
{
    uint32_t tree_height = SPX_TFORS_HEIGHT;
    uint32_t max_leaf_idx = (1u << tree_height) - 1;
    
    // 1. 确定需要哪些认证节点
    octopus_auth auth_indices;
    octopus_compute(&auth_indices, indices);
    
    // 2. 初始化认证节点数组
    auth->count = auth_indices.count;
    for (uint32_t i = 0; i < auth_indices.count; i++) {
        auth->entries[i].level = auth_indices.entries[i].level;
        auth->entries[i].index = auth_indices.entries[i].index;
        memset(auth->entries[i].hash, 0, SPX_N);
    }
    
    // 3. 为目标叶子创建快速查找表
    unsigned char *target_hash = (unsigned char*)malloc((max_leaf_idx + 1) * SPX_N);
    uint8_t *is_target = (uint8_t*)malloc(max_leaf_idx + 1);
    
    if (!target_hash || !is_target) {
        fprintf(stderr, "Error: malloc failed\n");
        if (target_hash) free(target_hash);
        if (is_target) free(is_target);
        memset(root, 0, SPX_N);
        return;
    }
    
    memset(is_target, 0, max_leaf_idx + 1);
    
    // 4. 计算每个目标叶子的哈希
    for (uint32_t i = 0; i < leaf_count; i++) {
        uint32_t leaf_idx = indices[i];
        is_target[leaf_idx] = 1;

        // printf("tfors_sign: pub_seed = ");
        // for(int i=0; i<SPX_N && i<16; i++) printf("%02x", ctx->pub_seed[i]);
        // printf("\n");

        uint32_t tfors_leaf_addr[8] = {0};
        copy_keypair_addr(tfors_leaf_addr, tree_addr);
        set_type(tfors_leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
        set_tree_height(tfors_leaf_addr, 0);
        set_tree_index(tfors_leaf_addr, indices[i]);
        // print_spx_addr("fors_leaf_addr (initial)", tfors_leaf_addr);
        
        tfors_sk_to_leaf(&target_hash[leaf_idx * SPX_N], leaf_sk[i], ctx, tfors_leaf_addr);
        
        // uint32_t leaf_addr[8];
        // memset(leaf_addr, 0, 8 * sizeof(uint32_t));
        // copy_keypair_addr(leaf_addr, tree_addr);
        // set_type(leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
        // set_tree_height(leaf_addr, 0);
        // set_tree_index(leaf_addr, leaf_idx);
        
        // print_spx_addr("fors_leaf_addr (test)", leaf_addr);
        
        // thash(&target_hash[leaf_idx * SPX_N], leaf_sk[i], 1, ctx, leaf_addr);
        
        // printf("leaf sk: ");
        // for (int j = 0; j < SPX_N; j++) {
        //     printf("%02x", leaf_sk[i][j]);
        // }
        // printf("leaf hash: ");
        // for (int j = 0; j < SPX_N; j++) {
        //     printf("%02x", target_hash[leaf_idx * SPX_N + j]);
        // }
        // printf("\n\n");
    }
    
    // 5. 使用栈遍历所有叶子
    unsigned char stack[SPX_TFORS_HEIGHT * SPX_N];
    uint32_t stack_top = 0;
    
    for (uint32_t idx = 0; idx <= max_leaf_idx; idx++) {
        unsigned char current[2 * SPX_N];
        
        // 获取当前叶子的哈希
        if (is_target[idx]) {
            memcpy(&current[SPX_N], &target_hash[idx * SPX_N], SPX_N);
        } else {
            unsigned char sk[SPX_N];
            uint32_t leaf_addr[8];
            memset(leaf_addr, 0, 8 * sizeof(uint32_t));
            copy_keypair_addr(leaf_addr, tree_addr);
            set_tree_height(leaf_addr, 0);
            set_tree_index(leaf_addr, idx);
            set_type(leaf_addr, SPX_ADDR_TYPE_TFORSPRF);
            prf_addr(sk, ctx, leaf_addr);
            set_type(leaf_addr, SPX_ADDR_TYPE_TFORSTREE);
            thash(&current[SPX_N], sk, 1, ctx, leaf_addr);
        }
        
        // 向上合并
        uint32_t node_idx = idx;
        uint32_t h;
        
        for (h = 0;; h++) {
            uint32_t sibling_idx = node_idx ^ 1;
            
            // 检查兄弟节点是否是需要的认证节点
            for (uint32_t i = 0; i < auth->count; i++) {
                if (auth->entries[i].level == h && 
                    auth->entries[i].index == node_idx) {
                    memcpy(auth->entries[i].hash, &current[SPX_N], SPX_N);
                    break;
                }
            }
            
            // 如果是左孩子且不是最后一个叶子，暂停向上
            if ((node_idx & 1) == 0 && idx < max_leaf_idx) {
                break;
            }
            
            // 需要向上合并
            if (stack_top > 0) {
                unsigned char *left = &stack[(stack_top - 1) * SPX_N];
                unsigned char *right = &current[SPX_N];
                
                memcpy(&current[0], left, SPX_N);
                
                uint32_t parent_addr[8];
                uint32_t parent_idx = node_idx / 2;
                memset(parent_addr, 0, 8 * sizeof(uint32_t));
                copy_keypair_addr(parent_addr, tree_addr);
                set_tree_height(parent_addr, h + 1);
                set_tree_index(parent_addr, parent_idx);
                set_type(parent_addr, SPX_ADDR_TYPE_TFORSTREE);
                
                thash(&current[SPX_N], &current[0], 2, ctx, parent_addr);
                
                stack_top--;
                node_idx = parent_idx;
            } else {
                break;
            }
        }
        
        // 将当前节点压入栈
        memcpy(&stack[stack_top * SPX_N], &current[SPX_N], SPX_N);
        stack_top++;
    }
    
    // 6. 准备叶子哈希数组
    unsigned char leaf_hashes[SPX_TFORS_K][SPX_N];
    for (uint32_t i = 0; i < leaf_count; i++) {
        uint32_t leaf_idx = indices[i];
        memcpy(leaf_hashes[i], &target_hash[leaf_idx * SPX_N], SPX_N);
    }
    
    // 7. 重建根
    octopus_recompute_root(root, indices, leaf_count, auth,
                          (const unsigned char*)leaf_hashes,
                          ctx, tree_addr);
    
    free(target_hash);
    free(is_target);
}

// 从认证路径重建根节点
void octopus_recompute_root(unsigned char root[SPX_N],
                           const uint32_t *indices,
                           uint32_t leaf_count,
                           const octopus_auth_with_hash *auth,
                           const unsigned char *leaf_hashes,
                           const spx_ctx *ctx,
                           uint32_t tree_addr[8])
{
    typedef struct {
        uint32_t index;
        unsigned char hash[SPX_N];
    } node_entry;
    
    node_entry current_nodes[SPX_TFORS_K];
    uint32_t current_len = leaf_count;
    
    // 初始化当前层为所有叶子节点
    for (uint32_t i = 0; i < leaf_count; i++) {
        current_nodes[i].index = indices[i];
        memcpy(current_nodes[i].hash, leaf_hashes + i * SPX_N, SPX_N);
    }
    
    // 排序当前层
    qsort(current_nodes, current_len, sizeof(node_entry), 
          (int (*)(const void*, const void*))cmp_uint32);
    
    // 逐层向上计算
    for (uint32_t level = 0; level < SPX_TFORS_HEIGHT; level++) {
        unsigned char current[2 * SPX_N];
        node_entry parent_nodes[SPX_TFORS_K];
        uint32_t parent_len = 0;
        uint32_t i = 0;
        
        while (i < current_len) {
            uint32_t node_idx = current_nodes[i].index;
            uint32_t parent_idx = node_idx / 2;
            uint32_t sibling_idx = node_idx ^ 1;
            
            const unsigned char *sibling_hash = NULL;
            int has_sibling = 0;
            
            // 检查是否在当前节点列表
            if (i + 1 < current_len && current_nodes[i + 1].index == sibling_idx) {
                sibling_hash = current_nodes[i + 1].hash;
                has_sibling = 1;
            } else {
                // 从认证路径查找
                for (uint32_t j = 0; j < auth->count; j++) {
                    if (auth->entries[j].level == level && 
                        auth->entries[j].index == sibling_idx) {
                        sibling_hash = auth->entries[j].hash;
                        has_sibling = 1;
                        break;
                    }
                }
            }
            
            if (!has_sibling) {
                fprintf(stderr, "Error: missing sibling at level %u, index %u\n", 
                        level, sibling_idx);
                memset(root, 0, SPX_N);
                return;
            }
            
            // 计算父节点
            unsigned char parent_hash[SPX_N];
            uint32_t node_addr[8];
            memset(node_addr, 0, 8 * sizeof(uint32_t));
            copy_keypair_addr(node_addr, tree_addr);
            set_tree_height(node_addr, level + 1);
            set_tree_index(node_addr, parent_idx);
            set_type(node_addr, SPX_ADDR_TYPE_TFORSTREE);

            if (node_idx % 2 == 0) {
                memcpy(&current[0], current_nodes[i].hash, SPX_N);
                memcpy(&current[SPX_N], sibling_hash, SPX_N);
            } else {
                memcpy(&current[0], sibling_hash, SPX_N);
                memcpy(&current[SPX_N], current_nodes[i].hash, SPX_N);
            }
            thash(parent_hash, current, 2, ctx, node_addr);
            
            // 保存父节点
            parent_nodes[parent_len].index = parent_idx;
            memcpy(parent_nodes[parent_len].hash, parent_hash, SPX_N);
            parent_len++;
            
            if (has_sibling && i + 1 < current_len && current_nodes[i + 1].index == sibling_idx) {
                i += 2;
            } else {
                i += 1;
            }
        }
        
        if (parent_len == 0) {
            fprintf(stderr, "Error: no parent nodes at level %u\n", level);
            memset(root, 0, SPX_N);
            return;
        }
        
        memcpy(current_nodes, parent_nodes, parent_len * sizeof(node_entry));
        current_len = parent_len;
        
        qsort(current_nodes, current_len, sizeof(node_entry),
              (int (*)(const void*, const void*))cmp_uint32);
    }
    
    if (current_len == 1) {
        memcpy(root, current_nodes[0].hash, SPX_N);
    } else {
        fprintf(stderr, "Error: expected 1 root, got %u\n", current_len);
        memset(root, 0, SPX_N);
    }
}