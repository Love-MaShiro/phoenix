#include "octopus.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "context.h"
#include "address.h"
#include "thash.h"
#include "utils.h"
#include "tfors.h"

// remove duplicates
static uint32_t unique_uint32(uint32_t *arr, uint32_t len) {
    uint32_t idx = 1;
    if (len == 0) return 0;
    
    for (uint32_t i = 1; i < len; i++) {
        if (arr[i] != arr[i-1]) {
            arr[idx++] = arr[i];
        }
    }
    return idx;
}

void octopus_compute_auth_count(const uint32_t *indices, uint32_t len, uint32_t *auth_count) {
    uint32_t current[SPX_TFORS_K];
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
            current[parent_len++] = idx / 2;
        }
        if (parent_len == 0) break;
        current_len = unique_uint32(current, parent_len);
    }
    *auth_count = count;
}

void octopus_compute(octopus_auth *auth,
                     const uint32_t *indices)
{
    uint32_t current_indices[SPX_TFORS_K];
    uint32_t parent_indices[SPX_TFORS_K];
    uint32_t current_len = SPX_TFORS_K;
    uint32_t tfors_height = SPX_TFORS_HEIGHT;

    memcpy(current_indices, indices, SPX_TFORS_K * sizeof(uint32_t));   
    auth->count = 0;
    
    // process from leaf layer to root layer    
    // add sibling nodes to auth indices
    for (uint32_t level = 0; level < tfors_height; level++) {

        uint32_t parent_len = 0;
        uint32_t i = 0;
        
        while (i < current_len) {
            uint32_t node_idx = current_indices[i];
            uint32_t parent_idx = node_idx / 2;
            uint32_t sibling_idx = node_idx ^ 1;
            
            // add parent node to auth indices
            parent_indices[parent_len++] = parent_idx;
            
            // check if sibling node is an auth index   
            if (i + 1 < current_len && current_indices[i + 1] == sibling_idx) {
                i += 2;
            } else {
                if (level < tfors_height) {
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
            parent_len = unique_uint32(parent_indices, parent_len);
            memcpy(current_indices, parent_indices, parent_len * sizeof(uint32_t));
            current_len = parent_len;
        } else {
            return;
        }
    }
}   

void octopus_compute_auth_paths(unsigned char root[SPX_N],
                                unsigned char *sig,
                                const uint32_t *indices,
                                uint32_t leaf_count,
                                const unsigned char leaf_sk[][SPX_N],
                                const spx_ctx *ctx,
                                uint32_t tree_addr[8])
{
    uint32_t tree_height = SPX_TFORS_HEIGHT;
    uint32_t max_leaf_idx = (1u << tree_height) - 1;
    uint32_t i;
    
    // 1. compute auth indices
    octopus_auth auth_indices;
    octopus_compute(&auth_indices, indices);
    
    // 2. generate auth paths       
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
    
    // 3. compute hash for each target leaf
    for (i = 0; i < leaf_count; i++) {
        is_target[indices[i]] = 1;
        set_tree_index(tree_addr, indices[i]);
        tfors_sk_to_leaf(&target_hash[indices[i] * SPX_N], leaf_sk[i], ctx, tree_addr);
    }
    
    // 4. traverse all leaf nodes
    unsigned char stack[SPX_TFORS_HEIGHT * SPX_N];
    unsigned char current[2 * SPX_N];
    uint32_t stack_top = 0;
    unsigned char sk[SPX_N];
    for (uint32_t idx = 0; idx <= max_leaf_idx; idx++) {
        // if it's a target leaf, use precomputed hash
        if (is_target[idx]) {
            memcpy(&current[SPX_N], &target_hash[idx * SPX_N], SPX_N);
        } else if (idx < SPX_TFORS_K * (1 << SPX_TFORS_A)) {
            // otherwise, if it's in valid leaf range, compute hash
            
            set_tree_index(tree_addr, idx);
            set_type(tree_addr, SPX_ADDR_TYPE_TFORSPRF);
            prf_addr(sk, ctx, tree_addr);
            
            set_type(tree_addr, SPX_ADDR_TYPE_TFORSTREE);
            tfors_sk_to_leaf(&current[SPX_N], sk, ctx, tree_addr);
        } else {
            // for invalid nodes, use all 0 hash
            memset(&current[SPX_N], 0, SPX_N);
        }
        
        // traverse upward
        uint32_t node_idx = idx;
        uint32_t h;
        
        for (h = 0;; h++) {
            uint32_t sibling_idx = node_idx ^ 1;
            
            // check if sibling node is an auth index
            for (i = 0; i < auth_indices.count; i++) {
                if (auth_indices.entries[i].level == h && 
                    auth_indices.entries[i].index == node_idx) {
                    memcpy(sig + i * SPX_N, &current[SPX_N], SPX_N);
                    break;
                }
            }
            
            // If it's the left child and not the last leaf, stopping moving upward 
            if ((node_idx & 1) == 0 && idx < max_leaf_idx) {
                break;
            }
            
            /* Need to merge upward */
            if (stack_top > 0) {
                unsigned char *left = &stack[(stack_top - 1) * SPX_N];
                memcpy(&current[0], left, SPX_N);

                uint32_t parent_idx = node_idx / 2;
                set_tree_height(tree_addr, h + 1);
                set_tree_index(tree_addr, parent_idx);
                
                thash(&current[SPX_N], &current[0], 2, ctx, tree_addr);
                
                stack_top--;
                node_idx = parent_idx;
            } else {
                break;
            }
        }
        
        // push current node to stack
        memcpy(&stack[stack_top * SPX_N], &current[SPX_N], SPX_N);
        stack_top++;
    }
    sig += auth_indices.count * SPX_N;

    if (stack_top != 1) {
        fprintf(stderr, "Error: stack should have exactly 1 element (root), got %u\n", stack_top);
        memset(root, 0, SPX_N);
        free(target_hash);
        free(is_target);
        return;
    }
    memcpy(root, stack, SPX_N);
    
    free(target_hash);
    free(is_target);
}

void octopus_recompute_root(unsigned char root[SPX_N],
                               const uint32_t *indices,
                               uint32_t leaf_count,
                               const octopus_auth_with_hash *auth,
                               const unsigned char *leaf_hashes,
                               const spx_ctx *ctx,
                               uint32_t tree_addr[8])
{
    node_entry current_nodes[SPX_TFORS_K];
    uint32_t current_len = leaf_count;
    unsigned char current[2 * SPX_N];
    
    // initialize current nodes with leaf hashes
    for (uint32_t i = 0; i < leaf_count; i++) {
        current_nodes[i].index = indices[i];
        memcpy(current_nodes[i].hash, leaf_hashes + i * SPX_N, SPX_N);
    }
    
    uint32_t auth_ptr = 0; 
    
    for (uint32_t level = 0; level < SPX_TFORS_HEIGHT; level++) {
        node_entry parent_nodes[SPX_TFORS_K];
        uint32_t parent_len = 0;
        uint32_t i = 0;
        
        while (i < current_len) {
            uint32_t idx = current_nodes[i].index;
            uint32_t parent_idx = idx / 2;
            uint32_t sibling_idx = idx ^ 1;
            
            unsigned char *sibling_hash;
            int skip_sibling = 0;
            
            if (i + 1 < current_len && current_nodes[i + 1].index == sibling_idx) {
                sibling_hash = current_nodes[i + 1].hash;
                skip_sibling = 1;
                } else {
                    // read auth hash from auth path
                    if (auth_ptr >= auth->count || 
                        auth->entries[auth_ptr].level != level || 
                        auth->entries[auth_ptr].index != sibling_idx) {
                        fprintf(stderr, "Error: auth path mismatch\n");
                        memset(root, 0, SPX_N);
                        return;
                    }
                    sibling_hash = auth->entries[auth_ptr++].hash;
                }   
            
            // compute parent node hash
            set_tree_height(tree_addr, level + 1);
            set_tree_index(tree_addr, parent_idx);
            
            
            if (idx % 2 == 0) {
                memcpy(&current[0], current_nodes[i].hash, SPX_N);
                memcpy(&current[SPX_N], sibling_hash, SPX_N);
            } else {
                memcpy(&current[0], sibling_hash, SPX_N);
                memcpy(&current[SPX_N], current_nodes[i].hash, SPX_N);
            }
            
            thash(parent_nodes[parent_len].hash, current, 2, ctx, tree_addr);
            parent_nodes[parent_len++].index = parent_idx;
            
            if (skip_sibling) {
                i += 2;
            } else {
                i += 1;
            }
        }
        
        memcpy(current_nodes, parent_nodes, parent_len * sizeof(node_entry));
        current_len = parent_len;
    }
    
    if (current_len == 1) {
        memcpy(root, current_nodes[0].hash, SPX_N);
    } else {
        memset(root, 0, SPX_N);
    }
}