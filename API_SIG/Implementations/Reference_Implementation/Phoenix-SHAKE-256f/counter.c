#include <stdint.h>

#include "params.h"
#include "counter.h"
#include "utils.h"

/* The GWOTSC counter is stored just after the WOTS signature and the tree authentication path*/
#define WOTS_COUNTER_OFFSET (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N)
/* FORS+C  counter is stored just after the randomization value */
/* Maybe we dont need counter for FORS+C here */
#define FORS_COUNTER_OFFSET (SPX_N)

void save_wots_counter(uint32_t counter, unsigned char *sig)
{
    ull_to_bytes(sig + WOTS_COUNTER_OFFSET, COUNTER_SIZE, counter);
}

/* The counter is stored just after the WOTS signature*/
uint32_t get_wots_counter(const unsigned char *sig)
{
    return (uint32_t)bytes_to_ull(sig + WOTS_COUNTER_OFFSET, COUNTER_SIZE);
}
/* FORS+C  counter is stored in the end */
void save_fors_counter(uint32_t counter, unsigned char *sig)
{
    ull_to_bytes(sig + FORS_COUNTER_OFFSET, COUNTER_SIZE, counter);
}

uint32_t get_fors_counter(const unsigned char *sig)
{
    return (uint32_t)bytes_to_ull(sig + FORS_COUNTER_OFFSET, COUNTER_SIZE);
}