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
    // 打开存储密钥、IV和密文的文件
    FILE *key_file = fopen("key.bin", "rb");
    FILE *iv_file = fopen("iv.bin", "rb");
    FILE *cipher_file = fopen("Ciphertext", "rb");

    if (key_file == NULL || iv_file == NULL || cipher_file == NULL) {
        printf("Error: Failed to open key, IV, and/or ciphertext file!");
        return 1;
    }

    // 分配密钥、IV和密文内存缓冲区
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    // 从文件中读取密钥、IV和密文
    fread(key, 1, 16, key_file);
    fread(iv, 1, 16, iv_file);
    fseek(cipher_file, 0L, SEEK_END);
    ciphertext_len = ftell(cipher_file);
    fseek(cipher_file, 0L, SEEK_SET);
    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) {
        printf("Error: Failed to allocate memory for ciphertext buffer.");
        return 1;
    }
    fread(ciphertext, 1, ciphertext_len, cipher_file);

    // 关闭key、iv和cipher_file三个文件
    fclose(key_file);
    fclose(iv_file);
    fclose(cipher_file);

    EVP_CIPHER_CTX *ctx;

    // 创建并初始化解密上下文
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // 设置SM4算法并初始化密钥和初始化向量
    if(1 != EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv))
        handleErrors();

    // 设置填充模式
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // 分配解密后的内存缓冲区
    size_t plaintext_len = ciphertext_len + EVP_CIPHER_block_size(EVP_sm4_ecb());
    unsigned char *plaintext = malloc(plaintext_len);

    // 对密文进行解密
    int len;
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // 完成解密过程，并将最后的解密块输出
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    // 将解密后的明文输出到文件中
    FILE *output_file = fopen("plaintext.txt", "w");
    if (output_file == NULL) {
        printf("Error: Failed to open plaintext output file!");
        return 1;
    }
    fwrite(plaintext, 1, plaintext_len, output_file);
    fclose(output_file);

    // 释放加密上下文和解密内存缓冲区
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    return 0;
}
