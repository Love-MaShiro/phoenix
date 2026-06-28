/* Phoenix-GWOTSCx1 interface
 *
 * Internal leaf generation interface for 1-way GWOTSC operations.
 */

#if !defined( GWOTSCX1_H_ )
#define GWOTSCX1_H_

#include <string.h>

/* Leaf info for GWOTSC signature generation and PK computation */
struct leaf_info_x1 {
    unsigned char *gwotsc_sig;
    uint32_t gwotsc_sign_leaf;
    uint32_t *gwotsc_steps;
    uint32_t leaf_addr[8];
    uint32_t pk_addr[8];
};

/* Initialize leaf_info for timing-equivalent benchmark mode */
#define INITIALIZE_LEAF_INFO_X1(info, addr, step_buffer) { \
    info.gwotsc_sig = 0;             \
    info.gwotsc_sign_leaf = ~0u;      \
    info.gwotsc_steps = step_buffer; \
    memcpy( &info.leaf_addr[0], addr, 32 ); \
    memcpy( &info.pk_addr[0], addr, 32 ); \
}

#define gwotsc_gen_leafx1 PH_NAMESPACE(gwotsc_gen_leafx1)
void gwotsc_gen_leafx1(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info);

#endif /* GWOTSCX1_H_ */
