#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

const char* SIG_NAME = "SHA256";

typedef struct {
    EVP_PKEY *keys;
    OSSL_LIB_CTX *ctx;
} Signer;

typedef struct {
    unsigned char *bytes;
    size_t len;
} EthSig;


Signer* new_signer(OSSL_LIB_CTX *ctx) {
    EVP_PKEY *pkey = EVP_EC_gen("P-256");

    Signer *signer = malloc(sizeof(Signer));
    signer->keys = pkey;
    signer->ctx = ctx;

    return signer;
}

EthSig *sign_data(Signer *signer, const char* data, size_t data_len) {
    size_t sig_len;
    int ret = 0, public =0;

    EthSig *sig = malloc(sizeof(EthSig));

    EVP_MD_CTX *sign_context = EVP_MD_CTX_new();
    if(sign_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_NEW failed \n");
        goto cleanup;
    }

    if (!EVP_DigestSignInit_ex(sign_context, NULL, SIG_NAME, signer->ctx, NULL, signer->keys, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        goto cleanup;
    }

    if(!EVP_DigestSignUpdate(sign_context, data, data_len)) {
        fprintf(stderr, "EVP_DigestSignUpdate failed, \n");
        goto cleanup;
    }

    if(!EVP_DigestSignFinal(sign_context, NULL, &sig->len)) {
        fprintf(stderr, "sign() EVP_DigestSignFinal failed to get signature length\n");
        goto cleanup;
    }

    if(&sig->len <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal retunred invalid signature length\n");
        goto cleanup;
    }


    sig->bytes = OPENSSL_malloc(sig_len);
    if (sig->bytes == NULL) {
        fprintf(stderr, "sign error(): No memory to allocate signature");
    }

    if(!EVP_DigestSignFinal(sign_context, sig->bytes, &sig_len)) {
        fprintf(stderr, "sign() EVP_DigestSignFinal failed to finalise signature\n");
        goto cleanup;
    }

    return sig;

    cleanup:
        if(sig->bytes) {
            OPENSSL_free(sig->bytes);
        }

        free(sig);

        EVP_MD_CTX_free(sign_context);
        return NULL;
}
