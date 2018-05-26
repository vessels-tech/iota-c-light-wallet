#include "transfers.h"

#include <string.h>
#include <assert.h>
// iota-related stuff
#include "conversion.h"
#include "addresses.h"
#include "bundle.h"
#include "signing.h"
#include "../aux.h"
#include <math.h>
#include <stdio.h>
#include <malloc.h>

#define ZERO_HASH                                                              \
    "999999999999999999999999999999999999999999999999999999999999999999999999" \
    "999999999"
#define ZERO_TAG "999999999999999999999999999"

typedef struct TX_OBJECT {
    char signatureMessageFragment[2187];
    char address[81];
    int64_t value;
    char obsoleteTag[27];
    uint32_t timestamp;
    uint32_t currentIndex;
    uint32_t lastIndex;
    char bundle[81];
    char trunkTransaction[81];
    char branchTransaction[81];
    char tag[27];
    uint32_t attachmentTimestamp;
    uint32_t attachmentTimestampLowerBound;
    uint32_t attachmentTimestampUpperBound;
    char nonce[27];
} TX_OBJECT;

static const TX_OBJECT DEFAULT_TX = {
        {0}, ZERO_HASH, 0, ZERO_TAG, 0, 0, 0, ZERO_HASH,
        ZERO_HASH, ZERO_HASH, ZERO_TAG, 0, 0, 0, ZERO_TAG};

static char *int64_to_chars(int64_t value, char *chars, unsigned int num_trytes) {
    trit_t trits[num_trytes * 3];
    int64_to_trits(value, trits, num_trytes * 3);
    trits_to_chars(trits, chars, num_trytes * 3);

    return chars + num_trytes;
}

static void get_address(const unsigned char *seed_bytes, uint32_t idx,
                        unsigned int security, char *address) {
    unsigned char bytes[48];
    get_public_addr(seed_bytes, idx, security, bytes);
    bytes_to_chars(bytes, address, 48);
}

static char *char_copy(char *destination, const char *source, unsigned int len) {
    assert(strnlen(source, len) == len);
    memcpy(destination, source, len);

    return destination + len;
}

static char *int8_copy(char *destination, const uint8_t source) {
    memcpy(destination, &source, sizeof(uint8_t));

    return destination + sizeof(uint8_t);
}

static char * int16_copy(char *destination, const uint16_t source) {
    memcpy(destination, &source, sizeof(uint16_t));

    return destination + sizeof(uint16_t);
}

static char * int32_copy(char *destination, const uint32_t source) {
    memcpy(destination, &source, sizeof(uint32_t));

    return destination + sizeof(uint32_t);
}

uint16_t get_non_nine_len(char *signatureMessageFragment, uint16_t len) {
    uint16_t last_index = (uint16_t) (len - 1);
    if (
            signatureMessageFragment[last_index - 1] == '9' &&
            signatureMessageFragment[last_index] == '9'
            ) {
        return get_non_nine_len(signatureMessageFragment, (uint16_t) (len - 1));
    } else {
        return len;
    }
}

uint8_t is_zero(char *content, uint16_t len) {
    if (
            content[0] == '9' &&
            content[1] == '9' &&
            content[2] == '9' &&
            content[len - 1] == '9'
            ) {
        return 1;
    }else{
        return 0;
    }
}

char * get_compress_header_bytes(TX_OBJECT *txs, char *header_bytes, uint32_t num_txs){

    header_bytes = int32_copy(header_bytes, num_txs);

    uint8_t has_transaction_message[num_txs];

    int i = 0;
    for (int index = num_txs; index > 0; index--) {
        if(is_zero(txs[index - 1].signatureMessageFragment, 2187)){
            int8_copy(&has_transaction_message[i], 0);
        }else{
            int8_copy(&has_transaction_message[i], 1);
        }
        header_bytes = int8_copy(header_bytes, has_transaction_message[i]);

        i++;
    }

    uint8_t has_tag[num_txs];
    i = 0;
    for (int index = num_txs; index > 0; index--) {
        if(is_zero(txs[index - 1].obsoleteTag, 27)){
            int8_copy(&has_tag[i], 0);
        }else{
            int8_copy(&has_tag[i], 1);
        }
        header_bytes = int8_copy(header_bytes, has_tag[i]);

        i++;
    }


    unsigned char byte_bundle_hash[48];
    chars_to_bytes(txs[0].bundle, byte_bundle_hash, 81);
    memcpy(header_bytes, byte_bundle_hash, 48);

    return header_bytes + 48;
}

char * get_tx_number_by_compress_header(char * transaction_header, uint32_t * num_txs){
    int32_copy((char *) num_txs, (uint32_t) *transaction_header);

    return transaction_header + sizeof(uint32_t);
}

void parse_compressed_header(
        char * transaction_header,
        uint32_t num_txs,
        uint8_t * has_transaction_message,
        char char_bundle_hash[81]
){
    printf("\nTX COUNT: %i\n", num_txs);

    for(int i = 0; i < num_txs; i++){
        int8_copy(has_transaction_message + i, *transaction_header);
        printf("\nHAS TX MESSAGE: %i\n", has_transaction_message[i]);
        transaction_header = transaction_header + sizeof(uint8_t);
    }


    unsigned char bytes_bundle_hash[48];
    memcpy(bytes_bundle_hash, transaction_header, 48);

    bytes_to_chars(bytes_bundle_hash, char_bundle_hash, 48);
    printf("\nBUNDLEEEE: %.*s\n\n", 81, char_bundle_hash);

}

static void get_compressed_transaction_bytes(const TX_OBJECT *txs, char *transaction_header, char transaction_bytes[][1584], uint32_t num_txs) {
    char transactions_chars[num_txs][2673];

    char * start_ptr = transaction_header + 4;
    uint8_t has_transaction_message[num_txs];
    uint8_t has_tag[num_txs];

    int i = 0;
    for(int index = num_txs; index > 0; index--){
        has_transaction_message[index -1] = (uint8_t)*(start_ptr + i);
        i++;
    }

    i = 0;
    for(int index = num_txs; index > 0; index--){
        has_tag[index -1] = (uint8_t)*(start_ptr + i);
        i++;
    }

    i = 0;
    for(int index = num_txs; index > 0; index--){

        unsigned int char_count = 0;
        TX_OBJECT tx = txs[i];

        char *c = transactions_chars[index -1];
        c = char_copy(c, tx.address, 81);
        c = int64_to_chars(tx.value, c, 27);
        c = int64_to_chars(tx.currentIndex, c, 9);
        c = int64_to_chars(tx.lastIndex, c, 9);
        c = char_copy(c, tx.tag, 27);
        c = char_copy(c, tx.obsoleteTag, 27);

        printf("\nI: %i\n", i);
        printf("\nADDRESS:\n%s\n", tx.address);
        printf("\nVALUE:\n%i\n", tx.value);
        printf("\nCURRENT INDEX:\n%i\n", tx.currentIndex);
        printf("\nLAST INDEX:\n%i\n", tx.lastIndex);
        printf("\nTAG:\n%s\n", tx.tag);

        char_count = char_count + 153;

        for(int i = 0; i < 9; i++){
            c = char_copy(c, "9", 1);
            char_count = char_count + 1;
        }

        printf("\nHAS MESSAGE: %i \n", has_transaction_message[i]);
        printf("\nSIGNATURE:\n%s\n", tx.signatureMessageFragment);


        if(has_transaction_message[i]){
            c = char_copy(c, tx.signatureMessageFragment, 2187);
            char_count = char_count + 2187;
        }

        memcpy(transactions_chars[index -1] + char_count, "\0", 1);
        printf("\nCHAR CNT: %i\n", char_count);
        printf("\nTX STRING:\n%s\n", transactions_chars[index -1]);

        chars_to_bytes(transactions_chars[index -1], (unsigned char *) transaction_bytes[i], char_count);
        printf("TX BYTES: %.*s\n", 1584, transaction_bytes[i]);

        i++;
    }
}

static void get_transaction_chars(const TX_OBJECT tx, char *transaction_chars) {
    // just to make sure
    memset(transaction_chars, '\0', 2673);

    char *c = transaction_chars;

    c = char_copy(c, tx.signatureMessageFragment, 2187);
    c = char_copy(c, tx.address, 81);
    c = int64_to_chars(tx.value, c, 27);
    c = char_copy(c, tx.obsoleteTag, 27);
    c = int64_to_chars(tx.timestamp, c, 9);
    c = int64_to_chars(tx.currentIndex, c, 9);
    c = int64_to_chars(tx.lastIndex, c, 9);
    c = char_copy(c, tx.bundle, 81);
    c = char_copy(c, tx.trunkTransaction, 81);
    c = char_copy(c, tx.branchTransaction, 81);
    c = char_copy(c, tx.tag, 27);
    c = int64_to_chars(tx.attachmentTimestamp, c, 9);
    c = int64_to_chars(tx.attachmentTimestampLowerBound, c, 9);
    c = int64_to_chars(tx.attachmentTimestampUpperBound, c, 9);
    char_copy(c, tx.nonce, 27);
}

static void increment_obsolete_tag(unsigned int tag_increment, TX_OBJECT *tx) {
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tx->obsoleteTag, NUM_HASH_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    // TODO: do we need to increment both? Probably only obsoleteTag...
    memcpy(tx->obsoleteTag, extended_tag, 27);
    memcpy(tx->tag, extended_tag, 27);
}

static void set_bundle_hash(const BUNDLE_CTX *bundle_ctx, TX_OBJECT *txs,
                            unsigned int num_txs) {
    char bundle[81];
    bytes_to_chars(bundle_get_hash(bundle_ctx), bundle, 48);

    for (unsigned int i = 0; i < num_txs; i++) {
        memcpy(txs[i].bundle, bundle, 81);
    }
}


// return last tx index
int generate_output_objs(
        TX_OUTPUT *outputs, int num_outputs, TX_OBJECT *txs,
        uint32_t timestamp, const unsigned int last_tx_index
) {
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {

        // initialize with defaults
        memcpy(&txs[idx], &DEFAULT_TX, sizeof(TX_OBJECT));

        rpad_chars(txs[idx].signatureMessageFragment, outputs[i].message, 2187);
        memcpy(txs[idx].address, outputs[i].address, 81);
        txs[idx].value = outputs[i].value;
        rpad_chars(txs[idx].obsoleteTag, outputs[i].tag, 27);
        txs[idx].timestamp = timestamp;
        txs[idx].currentIndex = (uint32_t) idx;
        txs[idx].lastIndex = last_tx_index;
        rpad_chars(txs[idx].tag, outputs[i].tag, 27);
        idx++;
    }

    return idx;
}

void generate_input_objs(
        TX_INPUT *inputs, int num_inputs, TX_OBJECT *txs, uint32_t timestamp,
        const unsigned int last_tx_index, uint8_t security,
        unsigned char *seed_bytes, int idx
) {
    for (unsigned int i = 0; i < num_inputs; i++) {

        // initialize with defaults
        memcpy(&txs[idx], &DEFAULT_TX, sizeof(TX_OBJECT));

        char *address = txs[idx].address;
        get_address(seed_bytes, inputs[i].key_index, security, address);
        txs[idx].value = -inputs[i].balance;
        txs[idx].timestamp = timestamp;
        txs[idx].currentIndex = (uint32_t) idx;
        txs[idx].lastIndex = last_tx_index;
        idx++;

        // add meta transactions
        for (unsigned int j = 1; j < security; j++) {

            // initialize with defaults
            memcpy(&txs[idx], &DEFAULT_TX, sizeof(TX_OBJECT));

            memcpy(txs[idx].address, address, 81);
            txs[idx].value = 0;
            txs[idx].timestamp = timestamp;
            txs[idx].currentIndex = (uint32_t) idx;
            txs[idx].lastIndex = last_tx_index;
            idx++;
        }
    }
}

uint32_t create_bundle(BUNDLE_CTX *bundle_ctx, TX_OBJECT *txs, uint32_t num_txs) {

    bundle_initialize(bundle_ctx, num_txs - 1);

    for (unsigned int i = 0; i < num_txs; i++) {
        bundle_set_external_address(bundle_ctx, txs[i].address);
        bundle_add_tx(bundle_ctx, txs[i].value, txs[i].tag, txs[i].timestamp);
    }

    return bundle_finalize(bundle_ctx);
}

void sign_inputs(
        unsigned char seed_bytes[48], uint8_t security, TX_OBJECT *txs, TX_INPUT *inputs,
        tryte_t normalized_bundle_hash[81], int num_inputs, int num_outputs
) {

    for (unsigned int i = 0; i < num_inputs; i++) {
        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].key_index,
                           security, normalized_bundle_hash);
        unsigned int idx = num_outputs + i * security;

        // exactly one fragment for transaction including meta transactions
        for (unsigned int j = 0; j < security; j++) {

            unsigned char signature_bytes[27 * 48];
            signing_next_fragment(&signing_ctx, signature_bytes);
            bytes_to_chars(signature_bytes, txs[idx++].signatureMessageFragment,
                           27 * 48);
        }
    }
}

TX_OBJECT *get_transaction_objs(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        TX_OBJECT *txs
) {
    // TODO use a proper timestamp
    const uint32_t timestamp = 0;
    const unsigned int num_txs = (unsigned int) (num_outputs + num_inputs * security);
    const unsigned int last_tx_index = num_txs - 1;

    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);

    int idx = generate_output_objs(outputs, num_outputs, txs, timestamp, last_tx_index);
    generate_input_objs(inputs, num_inputs, txs, timestamp, last_tx_index, security, seed_bytes, idx);

    // create a secure bundle
    BUNDLE_CTX bundle_ctx;

    uint32_t tag_increment = create_bundle(&bundle_ctx, txs, num_txs);

    // increment the tag in the first transaction object
    increment_obsolete_tag(tag_increment, &txs[0]);

    // set the bundle hash in all transaction objects
    set_bundle_hash(&bundle_ctx, txs, num_txs);

    // sign the inputs
    tryte_t normalized_bundle_hash[81];
    bundle_get_normalized_hash(&bundle_ctx, normalized_bundle_hash);

    sign_inputs(seed_bytes, security, txs, inputs, normalized_bundle_hash, num_inputs, num_outputs);

    return txs;
}

char * create_transfer_compress_bytes(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_bytes[][1584]
) {
    const unsigned int num_txs = (unsigned int) (num_outputs + num_inputs * security);

    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);

    // first create the transaction objects
    TX_OBJECT txs[num_txs];

    get_transaction_objs(seed, security, outputs, num_outputs, inputs, num_inputs, txs);

    char * transaction_header = (char *) malloc((4 + (num_txs * 8) + 48) * sizeof(char));
    get_compress_header_bytes(txs, transaction_header, num_txs);

    printf("\nNUMER TXS:\n%i\n", num_txs);
    get_compressed_transaction_bytes(txs, transaction_header, transaction_bytes, num_txs);

    return transaction_header;
}


void create_transfer_chars(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_chars[][2673]
) {
    // TODO use a proper timestamp
    const uint32_t timestamp = 0;
    const unsigned int num_txs = (unsigned int) (num_outputs + num_inputs * security);
    const unsigned int last_tx_index = num_txs - 1;

    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);

    // first create the transaction objects
    TX_OBJECT txs[num_txs];

    get_transaction_objs(seed, security, outputs, num_outputs, inputs, num_inputs, txs);

    // convert everything into trytes
    for (unsigned int i = 0; i < num_txs; i++) {
        get_transaction_chars(txs[i], transaction_chars[last_tx_index - i]);
    }
}

void parse_compressed_tx(char transaction_bytes[1584], TX_OBJECT * tx){

}

void parse_compressed_bytes(char transaction_header[], char transaction_bytes[][1584], char transaction_chars[][2673]){
    uint32_t num_txs;
    transaction_header = get_tx_number_by_compress_header(transaction_header, &num_txs);
    uint8_t has_transaction_message[num_txs];
    char bundle_hash[81];
    parse_compressed_header(transaction_header, num_txs, has_transaction_message, bundle_hash);

    char compress_transaction_chars[num_txs][2673];

    for(int i = 0; i < num_txs; i++){
        uint32_t char_count = 162;

        if(has_transaction_message[i]){
            char_count = char_count + 2187;
        }


        bytes_to_chars(transaction_bytes[i], compress_transaction_chars[i], char_count);

        char * compressed = compress_transaction_chars[i];

        char address[81];
        char value[27];
        char currentIndex[9];
        char lastIndex[9];
        char tag[27];

        compressed = char_copy(address, compressed, 81);
        compressed = char_copy(value, compressed, 27);
        compressed = char_copy(currentIndex, compressed, 9);
        compressed = char_copy(lastIndex, compressed , 9);
        compressed = char_copy(tag, compressed, 27);

        char message[2187];
        if(has_transaction_message[i]){
            compressed = char_copy(message, compressed, 2187);
        }

        char trunkTransaction[81];
        char branchTransaction[81];
        char nonce[27];
        char * c = transaction_chars[i];

        c = char_copy(c, message, 2187);
        c = char_copy(c, address, 81);
        c = char_copy(c, value, 27);
        //c = char_copy(c, obsolote_tag, 27);
        c = int64_to_chars(0, c, 9);
        c = char_copy(c, currentIndex, 9);
        c = char_copy(c, lastIndex, 9);
        c = char_copy(c, bundle_hash, 81);
        c = char_copy(c, trunkTransaction, 81);
        c = char_copy(c, branchTransaction, 81);
        c = char_copy(c, tag, 27);
        c = int64_to_chars(0, c , 9);
        c = int64_to_chars(0, c, 9);
        c = int64_to_chars(0, c, 9);
        c = char_copy(c, nonce, 27);

    }
}

void create_transfer_bytes(
        char *seed, uint8_t security, TX_OUTPUT *outputs,
        int num_outputs, TX_INPUT *inputs, int num_inputs,
        char transaction_bytes[][1584]
) {
    const unsigned int num_txs = (unsigned int) (num_outputs + num_inputs * security);
    char transaction_chars[num_txs][2673];

    create_transfer_chars(seed, security, outputs, num_outputs, inputs, num_inputs, transaction_chars);

    for (int i = 0; i < num_txs; i++) {
        chars_to_bytes(transaction_chars[i], (unsigned char *) transaction_bytes[i], 2673);
    }
}


