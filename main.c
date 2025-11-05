#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

#include "signer.h"

int main() {

    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "failed to init openssl context");
        return 1;
    }

    Signer *s = new_signer(ctx);
    if (s == NULL) {
        fprintf(stderr, "failed to create a new signer");
        return 1;
    }

    const char* data = "some arbritary string len";
    EthSig *sig = sign_data(s, data, strlen(data));

    printf("signature (len=%zu): \n", sig->len);

    for(int i=0; i<sig->len; ++i) {
        printf("%02X", data[i]);

        if((i+1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
    return 0;
}

static int verify_sig(Signer *signer, OSSL_LIB_CTX *libctx, const char *sig_name,
                       size_t sig_len, unsigned char *sig_value)
{

    int ret = 0, public = 1;
    const char *propq = NULL;
    EVP_MD_CTX *verify_context = NULL;
    EVP_PKEY *pub_key = NULL;

    /*
     * Make a verify signature context to hold temporary state
     * during signature verification
     */
    verify_context = EVP_MD_CTX_new();

    if (verify_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /* Get public key */
    /* Verify */
    if (!EVP_DigestVerifyInit_ex(verify_context, NULL, SIG_NAME
                                libctx, NULL, pub_key, NULL)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestVerifyUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (!EVP_DigestVerifyUpdate(verify_context, hamlet_1, strlen(hamlet_1))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (!EVP_DigestVerifyUpdate(verify_context, hamlet_2, strlen(hamlet_2))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestVerifyFinal(verify_context, sig_value, sig_len) <= 0) {
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
