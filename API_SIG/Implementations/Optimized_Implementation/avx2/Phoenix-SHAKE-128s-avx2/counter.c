#include <stdint.h>

#include "params.h"
#include "counter.h"
#include "utils.h"

/* The GWOTSC counter is stored just after the GWOTSC signature and the tree authentication path*/
#define GWOTSC_COUNTER_OFFSET (PH_GWOTSC_BYTES + PH_TREE_HEIGHT * PH_N)
/* TFORS  counter is stored just after the randomization value */
/* Maybe we dont need counter for TFORS here */
#define TFORS_COUNTER_OFFSET (PH_N)

void save_gwotsc_counter(uint32_t counter, unsigned char *sig)
{
    ull_to_bytes(sig + GWOTSC_COUNTER_OFFSET, COUNTER_SIZE, counter);
}

/* The counter is stored just after the GWOTSC signature*/
uint32_t get_gwotsc_counter(const unsigned char *sig)
{
    return (uint32_t)bytes_to_ull(sig + GWOTSC_COUNTER_OFFSET, COUNTER_SIZE);
}
/* TFORS  counter is stored in the end */
void save_tfors_counter(uint32_t counter, unsigned char *sig)
{
    ull_to_bytes(sig + TFORS_COUNTER_OFFSET, COUNTER_SIZE, counter);
}

uint32_t get_tfors_counter(const unsigned char *sig)
{
    return (uint32_t)bytes_to_ull(sig + TFORS_COUNTER_OFFSET, COUNTER_SIZE);
}