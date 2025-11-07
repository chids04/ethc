#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

const char* HASH_NAME = "SHA3-256";

typedef struct {
    EVP_PKEY *pkey;
    OSSL_LIB_CTX *ctx;

} Signer;

typedef struct {
    unsigned char *bytes;
    size_t len;
} EthSig;


Signer* new_signer(OSSL_LIB_CTX *ctx) {
    EVP_PKEY *pkey = EVP_EC_gen("P-256");

    Signer *signer = malloc(sizeof(Signer));
    signer->pkey = pkey;
    signer->ctx = ctx;

    return signer;
}

// EVP_PKEY *to_pkey(const unsigned char *public_key) {
//     OSSL_DECODER_CTX *dctx = NULL;
//     EVP_PKEY *pkey = NULL;
//     int selection;
//     const unsigned char *data;
//     size_t data;

//     if(public) {
//         selection =EVP_PKEY_PUBLIC_KEY;
//         data = public_key;
//         data_len
//     }

// }

 int gen_pub_key(Signer *signer) {

    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if(EVP_PKEY_get_bn_param(signer->pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1) {
        fprintf(stderr, "error generating public key: invalid ec x param");
        return 1;
    }
    if(EVP_PKEY_get_bn_param(signer->pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
        fprintf(stderr, "error generating public key: invalid ec y param");
        return 1;
    }

    unsigned char xy[64];
    int x_len = BN_bn2binpad(x, xy, 32);
    int y_len = BN_bn2binpad(x, &xy[32], 32);

    if(x_len < 0 || y_len < 0) {
        fprintf(stderr, "invalid x and/or y values from ECDSA point curve");
        return 1;
    }

    BN_free(x);
    BN_free(y);

    // now we can hash this
    // and take last 20 bytes

    EVP_MD* pub_digest = EVP_MD_fetch(signer->ctx, HASH_NAME, NULL);

    unsigned int digest_len = EVP_MD_get_size(pub_digest);
    if(digest_len <= 0) {
        fprintf(stderr, "failed to create digest len for pub key");
        goto cleanup;
    }

    unsigned char* digest_val = OPENSSL_malloc(digest_len);
    if(digest_val == NULL) {
        fprintf(stderr, "failed to create digest value for pub key");
        goto cleanup;
    }

    EVP_MD_CTX *digest_ctx = EVP_MD_CTX_new();
    if(digest_ctx == NULL) {
        fprintf(stderr, "failed to create digest context for pub key");
        goto cleanup;
    }

    if(EVP_DigestInit(digest_ctx, pub_digest) != 1) {
        fprintf(stderr, "failed to init digest for pub key");
        goto cleanup;
    }

    if(EVP_DigestUpdate(digest_ctx, xy, sizeof(xy)) != 1) {
        fprintf(stderr, "failed to update digest for pub key");
        goto cleanup;
    }

    if(EVP_DigestFinal(digest_ctx, digest_val, &digest_len) != 1) {
        fprintf(stderr, "failed to finalise digest for pub key");
        goto cleanup;
    }

    unsigned char *pub = malloc(sizeof(unsigned char) * 20);
    memcpy(pub, digest_val + (size_t)digest_len - 20, 20);


    printf("full shortened generated pubkey (len %d): ", 20);
    for(unsigned int i=0; i<20; i++) {
        printf("%02x", pub[i]);
    }
    printf("\n");

    printf("full generated pubkey (len %d): ", digest_len);
    for(unsigned int i=0; i<digest_len; i++) {
        printf("%02x", digest_val[i]);
    }

    printf("\n");

    return 0;

    cleanup:
        EVP_MD_CTX_free(digest_ctx);
        EVP_MD_free(pub_digest);
        OPENSSL_free(digest_val);
        return 1;


    printf("len of x binary %d", x_len);
    printf("len of y binary %d", y_len);

}


EthSig *sign_data(Signer *signer, const char* data, size_t data_len) {
    EthSig *sig = malloc(sizeof(EthSig));

    EVP_MD_CTX *sign_context = EVP_MD_CTX_new();

    if(sign_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_NEW failed \n");
        goto cleanup;
    }

    if (!EVP_DigestSignInit_ex(sign_context, NULL, HASH_NAME, signer->ctx, NULL, signer->pkey, NULL)) {
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
    if (!EVP_DigestVerifyInit_ex(verify_context, NULL, HASH_NAME, libctx, NULL, pub_key, NULL)) {
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
