/* Phoenix-GWOTSC interface
 *
 * GWOTSC with variable-length chains for Phoenix signature scheme.
 */

#ifndef PH_GWOTSC_H
#define PH_GWOTSC_H

#include <stdint.h>

#include "params.h"
#include "context.h"

/* Derive chain lengths from message using base-w conversion. */
#define chain_lengths PH_NAMESPACE(chain_lengths)
unsigned int chain_lengths(unsigned int *lengths, const unsigned char *msg);

/* Reconstruct GWOTSC public key from signature using range-constrained chains. */
#define gwotsc_pk_from_sig PH_NAMESPACE(gwotsc_pk_from_sig)
void gwotsc_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8], uint32_t counter);

#endif /* PH_GWOTSC_H */
