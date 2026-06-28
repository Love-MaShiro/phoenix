#ifndef PH_ADDRESS_H
#define PH_ADDRESS_H

#include <stdint.h>
#include "params.h"

/* The hash types that are passed to set_type */
#define PH_ADDR_TYPE_GWOTSC 0
#define PH_ADDR_TYPE_GWOTSCPK 1
#define PH_ADDR_TYPE_HASHTREE 2
#define PH_ADDR_TYPE_TFORSTREE 3
#define PH_ADDR_TYPE_GWOTSCPRF 5
#define PH_ADDR_TYPE_TFORSPRF 6
#define PH_ADDR_TYPE_COMPRESS_GWOTSC 7


#define set_layer_addr PH_NAMESPACE(set_layer_addr)
void set_layer_addr(uint32_t tree_addr[8], uint32_t layer);

#define set_tree_addr PH_NAMESPACE(set_tree_addr)
void set_tree_addr(uint32_t tree_addr[8], uint64_t tree);

#define set_addr_type PH_NAMESPACE(set_addr_type)
void set_addr_type(uint32_t tree_addr[8], uint32_t type);

/* Copies the layer and tree part of one address into the other */
#define copy_tree_addr PH_NAMESPACE(copy_tree_addr)
void copy_tree_addr(uint32_t dest[8], const uint32_t src[8]);

/* These functions are used for GWOTSC and TFORS addresses. */

#define set_keypair_addr PH_NAMESPACE(set_keypair_addr)
void set_keypair_addr(uint32_t keypair_addr[8], uint32_t keypair);

#define set_chain_addr PH_NAMESPACE(set_chain_addr)
void set_chain_addr(uint32_t chain_addr[8], uint32_t chain);

#define set_hash_addr PH_NAMESPACE(set_hash_addr)
void set_hash_addr(uint32_t hash_addr[8], uint32_t hash);

#define copy_keypair_addr PH_NAMESPACE(copy_keypair_addr)
void copy_keypair_addr(uint32_t dest[8], const uint32_t src[8]);

/* These functions are used for all hash tree addresses (including TFORS). */

#define set_tree_height PH_NAMESPACE(set_tree_height)
void set_tree_height(uint32_t tfors_addr[8], uint32_t tfors_tree_height);

#define set_tree_index PH_NAMESPACE(set_tree_index)
void set_tree_index(uint32_t tfors_addr[8], uint32_t tfors_tree_index);

#endif



