#ifndef TRANSFERS_H
#define TRANSFERS_H

#include <stdint.h>

typedef struct TX_OUTPUT {
        char address[81];
        int64_t value;
        char message[2187];
        char tag[27];
} TX_OUTPUT;

typedef struct TX_INPUT {
        int64_t balance;
        uint32_t key_index;
} TX_INPUT;

char * create_transfer_compress_bytes(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_bytes[][1584]
);

void create_transfer_chars(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_chars[][2673]
);

void create_transfer_bytes(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_bytes[][1584]
);

void parse_compressed_bytes(
        char transaction_header[],
        char transaction_bytes[][1584],
        char transaction_chars[][2673]
);

#endif //TRANSFERS_H
