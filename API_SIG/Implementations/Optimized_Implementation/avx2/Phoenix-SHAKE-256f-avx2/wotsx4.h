#ifndef SPX_WOTSX4_H
#define SPX_WOTSX4_H

#include <stdint.h>

#include "params.h"

#define wots_gen_leafx4 SPX_NAMESPACE(wots_gen_leafx4)
void wots_gen_leafx4(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info);

#endif