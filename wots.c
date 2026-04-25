#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"


/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 * Support w=SPX_WOTS_W1 or w=SPX_WOTS_W2.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8],
                      uint32_t w)
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < w; i++)
    {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 */
static void base_w(unsigned int *output,
                   const unsigned char *input)
{
    int i, j;
    unsigned int offset = 0;

    /* Handle first part: W1 chain */
    for (i = 0; i < SPX_WOTS_W1_LEN; i++)
    {
        output[i] = 0;
        for (j = 0; j < SPX_WOTS_LOGW1; j++)
        {
            output[i] ^= ((input[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }

    /* Handle second part: W2 chain */
    for (i = SPX_WOTS_W1_LEN; i < SPX_WOTS_LEN1; i++)
    {
        output[i] = 0;
        for (j = 0; j < SPX_WOTS_LOGW2; j++)
        {
            output[i] ^= ((input[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}

/** 
 * Computes the checksum over a message (in variable base_w). 
 * Compare with the functions in sphincsplus, we treat void functions as functions with return values as done in sphincsplusc.
*/
static unsigned int wots_checksum(const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int i = 0;

    /* Compute checksum. */
    for (; i < SPX_WOTS_W1_LEN; i++)
    {
        csum += SPX_WOTS_W1 - 1 - msg_base_w[i];
    }

    for (; i < SPX_WOTS_W1_LEN + SPX_WOTS_W2_LEN; i++)
    {
        csum += SPX_WOTS_W2 - 1 - msg_base_w[i];
    }

    return csum;
}

/* Takes a message and derives the matching chain lengths. */
unsigned int chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    unsigned int csum;

    base_w(lengths, msg);
    csum = wots_checksum(lengths);
    return csum;
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 * Uses the range-constrained search logic with variable-length chains.
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8], uint32_t counter)
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;
    unsigned char bitmask[SPX_N];

    /*Initial parameters for validation of checksum*/
    int csum;
    unsigned char digest[SPX_N];

    /*Set thash address for custom hash to type 6 & PK format*/
    uint32_t wots_pk_addr[8] = {0};
    copy_subtree_addr(wots_pk_addr, addr);

    copy_keypair_addr(wots_pk_addr, addr); 
    set_type(wots_pk_addr, SPX_ADDR_TYPE_COMPRESS_WOTS);
    thash_init_bitmask(bitmask, 1, ctx, wots_pk_addr);

    /*Set padding*/
    ull_to_bytes(((unsigned char *)(wots_pk_addr)) + (SPX_OFFSET_COUNTER), COUNTER_SIZE, counter);
    /*Calculate checksum*/
    thash_fin(digest, msg, 1, ctx, wots_pk_addr, bitmask);


    memset(lengths, 0, sizeof(lengths));
    csum = chain_lengths(lengths, digest);
   
    /*Validate Checksum*/
    if ((csum < WOTS_SUM_BASE) ||
        (csum > (WOTS_SUM_BASE + WOTS_SUM_RANGE)))
    {
        /* Validation failed: invalidate the public key */
        memset(pk, 0, SPX_WOTS_BYTES);
    }
    else
    {
        /* Validation successful: proceed with PK reconstruction */

        /* Set the value of the last chain (the single checksum chain) */
        /* This chain signs the offset from the base sum */   
        lengths[SPX_WOTS_LEN1] = csum - WOTS_SUM_BASE;
        set_type(addr, SPX_ADDR_TYPE_WOTS); 
        ull_to_bytes(((unsigned char *)(addr)) + (SPX_OFFSET_COUNTER), COUNTER_SIZE, 0);

        /* Reconstruct W1 chains. */
        for (i = 0; i < SPX_WOTS_W1_LEN; i++)
        {
            set_chain_addr(addr, i);
            gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                      lengths[i], SPX_WOTS_W1 - 1 - lengths[i], ctx, addr, SPX_WOTS_W1);
        }

        /* Reconstruct W2 chains. */
        for (; i < SPX_WOTS_LEN1; i++)
        {
            set_chain_addr(addr, i);
            gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                      lengths[i], SPX_WOTS_W2 - 1 - lengths[i], ctx, addr, SPX_WOTS_W2);
        }

        /* Reconstruct checksum chain. */
        set_chain_addr(addr, i);
        gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                  lengths[i], SPX_WOTS_CHECKSUM_W - 1 - lengths[i], ctx, addr, SPX_WOTS_CHECKSUM_W);
    }
}
