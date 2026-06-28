#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "params.h"
#include "address.h"
#include "utils.h"
#include "gwotsc.h"



void save_gwotsc_counter(uint32_t counter, unsigned char *sig);

uint32_t get_gwotsc_counter(const unsigned char *sig);

void save_tfors_counter(uint32_t counter_bytes, unsigned char *sig);

uint32_t get_tfors_counter(const unsigned char *sig);