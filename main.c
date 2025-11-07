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

    for(size_t i=0; i < sig->len; ++i) {
        printf("%02X", data[i]);

        if((i+1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    printf("verifying signature \n");

    const char *new = "sig will now fail";

    if (verify_sig(s->ctx, s->pkey, sig, (const unsigned char*)new, strlen(new)) == 1) {
        printf("signature verfied\n");
    }
    else {
        fprintf(stderr, "signature invalid\n");
    }

    get_pub_key(s);

    return 0;
}
