#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    // 打开存储密钥和IV的文件
    FILE *key_file = fopen("key.bin", "rb");
    FILE *iv_file = fopen("iv.bin", "rb");

    if (key_file == NULL || iv_file == NULL) {
        printf("Error: Failed to open key and/or IV file!");
        return 1;
    }

    // 分配密钥和IV内存缓冲区
    unsigned char key[16];
    unsigned char iv[16];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    // 从文件中读取密钥和IV值
    fread(key, 1, 16, key_file);
    fread(iv, 1, 16, iv_file);

    // 关闭key和iv两个文件
    fclose(key_file);
    fclose(iv_file);

    // 明文和密文
    const char *plaintext = "20211120刘钟徽";
    size_t plaintext_len = strlen(plaintext);

    EVP_CIPHER_CTX *ctx;

    // 创建并初始化加密上下文
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // 设置SM4算法并初始化密钥和初始化向量
    if(1 != EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv))
        handleErrors();

    // 设置填充模式
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // 分配加密后的内存缓冲区
    size_t ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_sm4_ecb());
    unsigned char *ciphertext = malloc(ciphertext_len);

    // 对明文进行加密
    int len;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // 完成加密过程，并将最后的加密块输出
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    // 打印加密结果
    printf("Ciphertext: ");
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // 释放加密上下文和缓冲区内存
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    return 0;
}
