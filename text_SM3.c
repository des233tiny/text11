#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include<string.h>
void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    OpenSSL_add_all_digests();

    const EVP_MD* md = EVP_sm3();

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
    {
        handleErrors();
    }

    const char* message = "20211120刘钟徽";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (1 != EVP_DigestUpdate(mdctx, message, strlen(message)))
    {
        handleErrors();
    }

    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
    {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);

    int i;
    for (i = 0; i < digest_len; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
