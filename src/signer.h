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

    if(sig->len <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal retunred invalid signature length\n");
        goto cleanup;
    }


    sig->bytes = OPENSSL_malloc(sig->len);
    if (sig->bytes == NULL) {
        fprintf(stderr, "sign error(): No memory to allocate signature");
    }

    if(!EVP_DigestSignFinal(sign_context, sig->bytes, &sig->len)) {
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

int verify_sig(OSSL_LIB_CTX *libctx, EVP_PKEY* pub_key, EthSig *sig,
    const unsigned char *data, size_t data_len)
{

    int ret = 0;
    EVP_MD_CTX *verify_context = EVP_MD_CTX_new();

    if (verify_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }

    // verify
    if (!EVP_DigestVerifyInit_ex(verify_context, NULL, SIG_NAME, libctx, NULL, pub_key, NULL)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed.\n");
        goto cleanup;
    }

    if (!EVP_DigestVerifyUpdate(verify_context, data, data_len)) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(verify_context, sig->bytes
        , sig->len) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyFinal failed.\n");
        goto cleanup;
    }
    fprintf(stdout, "Signature verified.\n");
    ret = 1;

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_PKEY_free(pub_key);
    EVP_MD_CTX_free(verify_context);
    return ret;
}
