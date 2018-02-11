#ifndef ADDRESSES_H
#define ADDRESSES_H

#include "iota_types.h"

#define MAX_SECURITY 3

void get_public_addr(uint32_t *seed_bigint, uint32_t idx, uint8_t security,
                   uint32_t *address);

#endif // ADDRESSES_H
