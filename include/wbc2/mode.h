#ifndef WBC2_MODE_H
#define WBC2_MODE_H

#include<AisinoSSL/openssl/modes.h>
#include<feistalBox/feistalBox.h>
#include<stdio.h>
#include<stdlib.h>

typedef void (*whiteBox_block128_f)(const unsigned char in[16],
                           unsigned char out[16],
                           const void *table);

typedef void (*set_key_f)(void* key,const unsigned char* user_key);


void CRYPTO_wcbc128_encrypt(const unsigned char* in, unsigned char* out,
                            size_t len, const unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox);

void CRYPTO_wcbc128_decrypt(const unsigned char* in, unsigned char* out,
                            size_t len, const unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox);

void CRYTO_flatWhite128_encrypt();

void CRYTO_flatWhite128_decrypt();

#endif