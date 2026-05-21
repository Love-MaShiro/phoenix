#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "utilsx4.h"
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

static void gen_chains_x4(unsigned char *pk,
                          const unsigned char *sig,
                          const unsigned int *lengths,
                          uint32_t start_chain,
                          uint32_t count,
                          const spx_ctx *ctx,
                          const uint32_t addr[8],
                          uint32_t w)
{
    unsigned int starts[4] = {0, 0, 0, 0};
    unsigned int steps[4] = {0, 0, 0, 0};
    uint32_t addrx4[4 * 8] = {0};
    unsigned char dummy_in0[SPX_N] = {0};
    unsigned char dummy_in1[SPX_N] = {0};
    unsigned char dummy_in2[SPX_N] = {0};
    unsigned char dummy_in3[SPX_N] = {0};
    unsigned char dummy_out0[SPX_N];
    unsigned char dummy_out1[SPX_N];
    unsigned char dummy_out2[SPX_N];
    unsigned char dummy_out3[SPX_N];
    unsigned char *out[4] = {dummy_out0, dummy_out1, dummy_out2, dummy_out3};
    const unsigned char *in[4] = {dummy_in0, dummy_in1, dummy_in2, dummy_in3};
    uint32_t lane;

    for (lane = 0; lane < 4; lane++) {
        memcpy(addrx4 + lane * 8, addr, SPX_ADDR_BYTES);
        if (lane < count) {
            uint32_t chain = start_chain + lane;
            set_chain_addr(addrx4 + lane * 8, chain);
            out[lane] = pk + chain * SPX_N;
            in[lane] = sig + chain * SPX_N;
            starts[lane] = lengths[chain];
            steps[lane] = w - 1 - lengths[chain];
        }
    }

    chainx4(out[0], out[1], out[2], out[3],
            in[0], in[1], in[2], in[3],
            starts, steps, ctx, addrx4, w);
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
            unsigned int byte_pos = offset >> 3;
            unsigned int bit_in_byte = offset & 0x7;
            unsigned int bit = 0;
            if (byte_pos < SPX_N) {
                bit = (unsigned int)((input[byte_pos] >> bit_in_byte) & 0x1);
            }
            output[i] ^= bit << j;
            offset++;
        }
    }

    /* Handle second part: W2 chain */
    for (i = SPX_WOTS_W1_LEN; i < SPX_WOTS_LEN1; i++)
    {
        output[i] = 0;
        for (j = 0; j < SPX_WOTS_LOGW2; j++)
        {
            unsigned int byte_pos = offset >> 3;
            unsigned int bit_in_byte = offset & 0x7;
            unsigned int bit = 0;
            if (byte_pos < SPX_N) {
                bit = (unsigned int)((input[byte_pos] >> bit_in_byte) & 0x1);
            }
            output[i] ^= bit << j;
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
        uint32_t base_addr[8];

        set_type(addr, SPX_ADDR_TYPE_WOTS); 
        ull_to_bytes(((unsigned char *)(addr)) + (SPX_OFFSET_COUNTER), COUNTER_SIZE, 0);
        memcpy(base_addr, addr, sizeof(base_addr));

        /* Reconstruct W1 chains. */
        for (i = 0; i + 4 <= SPX_WOTS_W1_LEN; i += 4) {
            gen_chains_x4(pk, sig, lengths, i, 4, ctx, base_addr, SPX_WOTS_W1);
        }
        for (; i < SPX_WOTS_W1_LEN; i++) {
            set_chain_addr(addr, i);
            gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                      lengths[i], SPX_WOTS_W1 - 1 - lengths[i], ctx, addr, SPX_WOTS_W1);
        }

        /* Reconstruct W2 chains. */
        for (; i + 4 <= SPX_WOTS_LEN1; i += 4) {
            gen_chains_x4(pk, sig, lengths, i, 4, ctx, base_addr, SPX_WOTS_W2);
        }
        for (; i < SPX_WOTS_LEN1; i++) {
            set_chain_addr(addr, i);
            gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                      lengths[i], SPX_WOTS_W2 - 1 - lengths[i], ctx, addr, SPX_WOTS_W2);
        }

        if (SPX_WOTS_LEN2 > 0) {
            lengths[SPX_WOTS_LEN1] = (unsigned int)(csum - WOTS_SUM_BASE);
            set_chain_addr(addr, i);
            gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                      lengths[i], SPX_WOTS_CHECKSUM_W - 1 - lengths[i], ctx, addr, SPX_WOTS_CHECKSUM_W);
        }
    }
}
