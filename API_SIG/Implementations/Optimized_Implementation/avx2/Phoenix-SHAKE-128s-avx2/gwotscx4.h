/* Phoenix-GWOTSCx4 interface
 *
 * Internal leaf generation interface for 4-way parallel GWOTSC operations.
 */

#if !defined( GWOTSCX4_H_ )
#define GWOTSCX4_H_

#include <string.h>
#include "params.h"

/* Leaf info for 4-lane parallel GWOTSC signature generation */
struct leaf_info_x4 {
    unsigned char *gwotsc_sig;
    uint32_t gwotsc_sign_leaf;
    uint32_t *gwotsc_steps;
    uint32_t leaf_addr[4*8];
    uint32_t pk_addr[4*8];
};

/* Initialize leaf_info_x4 for timing-equivalent benchmark mode */
#define INITIALIZE_LEAF_INFO_X4(info, addr, step_buffer) { \
    info.gwotsc_sig = 0;             \
    info.gwotsc_sign_leaf = ~0;      \
    info.gwotsc_steps = step_buffer; \
    int lanepad_idx;                  \
    for (lanepad_idx = 0; lanepad_idx < 4; lanepad_idx++) {  \
        memcpy( &info.leaf_addr[8*lanepad_idx], addr, 32 ); \
        memcpy( &info.pk_addr[8*lanepad_idx], addr, 32 ); \
    } \
}

#define gwotsc_gen_leafx4 PH_NAMESPACE(gwotsc_gen_leafx4)
void gwotsc_gen_leafx4(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info);

#endif /* GWOTSCX4_H_ */
