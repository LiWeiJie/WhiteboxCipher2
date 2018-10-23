#ifndef WBC2_MODE_H
#define WBC2_MODE_H

#include<AisinoSSL/openssl/modes.h>
#include<feistalBox/feistalBox.h>
#include<stdio.h>
#include<stdlib.h>

#define WRAP_LEN 0
#define NOT_WRAP_LEN 1
#define ENC 1
#define DEC 0

typedef void (*whiteBox_block128_f)(const unsigned char in[16],
                           unsigned char out[16],
                           const void *table);

typedef void (*set_key_f)(void* key,const unsigned char* user_key);


size_t CRYPTO_wcbc128_encrypt(const unsigned char* in, unsigned char* out,
                            size_t len, unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox,uint8_t wrap_flag);

size_t CRYPTO_wcbc128_decrypt(const unsigned char* in, unsigned char* out,
                            size_t len, unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox,uint8_t wrap_flag);

size_t CRYPTO_wcfb128_encrypt(const unsigned char *in, unsigned char *out,
                                size_t len, unsigned char ivec[16],
                                block128_f block, set_key_f set_key, size_t type_size, int* num,
                                const void *table, whiteBox_block128_f whiteBox);

size_t CRYPTO_wcfb128_decrypt(const unsigned char* in, unsigned char* out,
                            size_t len, unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size, int* num,
                            const void* table, whiteBox_block128_f whiteBox);

#endif