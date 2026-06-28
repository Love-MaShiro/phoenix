#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "gwotsc.h"
#include "gwotscx1.h"
#include "address.h"
#include "params.h"

/* Compute chain value by iterating hash function from start position. */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8],
                      uint32_t w)
{
    uint32_t idx;
    memcpy(out, in, PH_N);

    for (idx = start; idx < (start + steps) && idx < w; idx++)
    {
        set_hash_addr(addr, idx);
        thash(out, out, 1, ctx, addr);
    }
}

/* Convert bytes to base-w integers for variable-length chain parameters. */
static void base_w(unsigned int *output,
                   const unsigned char *input)
{
    int seg_idx, bit_idx;
    unsigned int bit_offset = 0;

    /* W1 chain segment */
    for (seg_idx = 0; seg_idx < PH_GWOTSC_W1_LEN; seg_idx++)
    {
        output[seg_idx] = 0;
        for (bit_idx = 0; bit_idx < PH_GWOTSC_LOGW1; bit_idx++)
        {
            unsigned int byte_idx = bit_offset >> 3;
            unsigned int bit_pos = bit_offset & 0x7;
            unsigned int bit_val = 0;
            if (byte_idx < PH_N) {
                bit_val = (unsigned int)((input[byte_idx] >> bit_pos) & 0x1);
            }
            output[seg_idx] ^= bit_val << bit_idx;
            bit_offset++;
        }
    }

    /* W2 chain segment */
    for (seg_idx = PH_GWOTSC_W1_LEN; seg_idx < PH_GWOTSC_LEN1; seg_idx++)
    {
        output[seg_idx] = 0;
        for (bit_idx = 0; bit_idx < PH_GWOTSC_LOGW2; bit_idx++)
        {
            unsigned int byte_idx = bit_offset >> 3;
            unsigned int bit_pos = bit_offset & 0x7;
            unsigned int bit_val = 0;
            if (byte_idx < PH_N) {
                bit_val = (unsigned int)((input[byte_idx] >> bit_pos) & 0x1);
            }
            output[seg_idx] ^= bit_val << bit_idx;
            bit_offset++;
        }
    }
}

/* Compute checksum for message in variable base-w representation. */
static unsigned int gwotsc_checksum(const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int seg_idx = 0;

    for (seg_idx = 0; seg_idx < PH_GWOTSC_W1_LEN; seg_idx++)
    {
        csum += PH_GWOTSC_W1 - 1 - msg_base_w[seg_idx];
    }

    for (seg_idx = 0; seg_idx < PH_GWOTSC_W2_LEN; seg_idx++)
    {
        csum += PH_GWOTSC_W2 - 1 - msg_base_w[PH_GWOTSC_W1_LEN + seg_idx];
    }

    return csum;
}

/* Derive chain lengths from message using base-w conversion. */
unsigned int chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    unsigned int csum;
    base_w(lengths, msg);
    csum = gwotsc_checksum(lengths);
    return csum;
}

/* Reconstruct GWOTSC public key from signature using range-constrained chains. */
void gwotsc_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8], uint32_t counter)
{
    unsigned int lengths[PH_GWOTSC_LEN];
    uint32_t chain_idx;
    unsigned char bitmask[PH_N];
    int csum;
    unsigned char digest[PH_N];
    uint32_t gwotsc_pk_addr[8] = {0};

    copy_tree_addr(gwotsc_pk_addr, addr);
    copy_keypair_addr(gwotsc_pk_addr, addr);
    set_addr_type(gwotsc_pk_addr, PH_ADDR_TYPE_COMPRESS_GWOTSC);
    thash_init_bitmask(bitmask, 1, ctx, gwotsc_pk_addr);

    ull_to_bytes(((unsigned char *)(gwotsc_pk_addr)) + (PH_OFFSET_COUNTER), COUNTER_SIZE, counter);
    thash_fin(digest, msg, 1, ctx, gwotsc_pk_addr, bitmask);

    memset(lengths, 0, sizeof(lengths));
    csum = chain_lengths(lengths, digest);

    if ((csum < GWOTSC_SUM_BASE) ||
        (csum > (GWOTSC_SUM_BASE + GWOTSC_SUM_RANGE)))
    {
        memset(pk, 0, PH_GWOTSC_BYTES);
    }
    else
    {
        set_addr_type(addr, PH_ADDR_TYPE_GWOTSC);
        ull_to_bytes(((unsigned char *)(addr)) + (PH_OFFSET_COUNTER), COUNTER_SIZE, 0);

        /* W1 chain reconstruction */
        for (chain_idx = 0; chain_idx < PH_GWOTSC_W1_LEN; chain_idx++)
        {
            set_chain_addr(addr, chain_idx);
            gen_chain(pk + chain_idx * PH_N, sig + chain_idx * PH_N,
                      lengths[chain_idx], PH_GWOTSC_W1 - 1 - lengths[chain_idx], ctx, addr, PH_GWOTSC_W1);
        }

        /* W2 chain reconstruction */
        for (; chain_idx < PH_GWOTSC_LEN1; chain_idx++)
        {
            set_chain_addr(addr, chain_idx);
            gen_chain(pk + chain_idx * PH_N, sig + chain_idx * PH_N,
                      lengths[chain_idx], PH_GWOTSC_W2 - 1 - lengths[chain_idx], ctx, addr, PH_GWOTSC_W2);
        }

        /* Checksum chain reconstruction */
        if (PH_GWOTSC_LEN2 > 0) {
            lengths[PH_GWOTSC_LEN1] = (unsigned int)(csum - GWOTSC_SUM_BASE);
            set_chain_addr(addr, chain_idx);
            gen_chain(pk + chain_idx * PH_N, sig + chain_idx * PH_N,
                      lengths[chain_idx], PH_GWOTSC_CHECKSUM_W - 1 - lengths[chain_idx], ctx, addr, PH_GWOTSC_CHECKSUM_W);
        }
    }
}
