#ifndef OCTOPUS_H
#define OCTOPUS_H

#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "context.h"

// ==================== 数据结构定义 ====================

// 认证节点条目（只包含索引）
typedef struct {
    uint32_t level;
    uint32_t index;
} octopus_entry;

// Octopus 认证结构（只包含索引）
typedef struct {
    octopus_entry entries[SPX_TFORS_K * SPX_TFORS_HEIGHT];
    uint32_t count;
} octopus_auth;

// 认证节点条目（包含哈希值）
typedef struct {
    uint32_t level;
    uint32_t index;
    unsigned char hash[SPX_N];
} octopus_entry_with_hash;

// Octopus 认证结构（包含哈希值）
typedef struct {
    octopus_entry_with_hash entries[SPX_TFORS_K * SPX_TFORS_HEIGHT];
    uint32_t count;
} octopus_auth_with_hash;

// 叶子节点信息
typedef struct {
    uint32_t index;
    unsigned char hash[SPX_N];
    int is_target; // 是否为目标叶子节点
} leaf_info_t;

// ==================== 辅助函数声明 ====================

// 比较函数：用于排序
int cmp_uint32(const void *a, const void *b);

// 去重函数：对排序后的数组去重
uint32_t unique_uint32(uint32_t *arr, uint32_t len);

// ==================== 核心函数声明 ====================

void octopus_compute_auth_count(const uint32_t *indices, uint32_t len, uint32_t *auth_count);

// 生成去冗余的认证节点索引
void octopus_compute(octopus_auth *auth,
                     const uint32_t *indices);

// 生成去冗余的认证路径（直接生成哈希值）
void octopus_compute_auth_paths(unsigned char root[SPX_N],
                                octopus_auth_with_hash *auth,
                                const uint32_t *indices,
                                uint32_t leaf_count,
                                const unsigned char leaf_sk[][SPX_N],  // 新增：叶子私钥数组
                                const spx_ctx *ctx,
                                uint32_t tree_addr[8]);
                                // octopus.h

// 从认证路径重建根节点
void octopus_recompute_root(unsigned char root[SPX_N],
                           const uint32_t *indices,
                           uint32_t leaf_count,
                           const octopus_auth_with_hash *auth,
                           const unsigned char *leaf_hashes,
                           const spx_ctx *ctx,
                           uint32_t tree_addr[8]);

// // 快速计算认证节点数量
// uint32_t octopus_get_auth_count(const uint32_t *indices, uint32_t leaf_count);

#endif /* OCTOPUS_H */