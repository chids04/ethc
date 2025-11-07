#include "signer.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

#include <stdio.h>

typedef struct {
    EVP_PKEY *sender;
    EVP_PKEY *recv;
    unsigned int nonce;
    unsigned int amount;
    EthSig sig;

} Transaction;

void new_transaction( ) {
    // need to check sig to make sure its good
    // ensure nonce is valid

    // if (sender == NULL) {
    //     fprintf(stderr, "invalid sender");
    // }

};
