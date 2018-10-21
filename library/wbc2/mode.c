#include "wbc2/mode.h"
#include "AisinoSSL/internal/aisinossl_random.h"
#define KEY_SIZE 16
#define VECTOR_SIZE 16
#define BLOCK_SIZE 16


void gen_one_time_userkey(unsigned char* key,size_t key_size){
    aisinossl_random_context ctx;
    aisinossl_random_init(&ctx);
    aisinossl_random_seed(&ctx, NULL, 0);
    aisinossl_random_rand(&ctx, key, key_size);
    aisinossl_random_free(&ctx);
}

void CRYPTO_wcbc128_encrypt(const unsigned char* in, unsigned char* out,
                            size_t len, const unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox){
    if (len == 0)
        return;

    size_t i;
    unsigned char user_key[KEY_SIZE];
    unsigned char iv[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    void* key;

    gen_one_time_userkey(user_key, KEY_SIZE);
    memcpy(iv, ivec, VECTOR_SIZE);
    for(i = 0; i < VECTOR_SIZE; i++)
        iv[i] ^= user_key[i];
    (*whiteBox) (iv, block_iv, table);

    memcpy(out, block_iv, VECTOR_SIZE);
    out += BLOCK_SIZE;

    key = malloc(type_size);
    (*set_key) (key, user_key);
    CRYPTO_cbc128_encrypt(in, out, len, key, block_iv, block);
    free(key);
}

void CRYPTO_wcbc128_decrypt(const unsigned char* in, unsigned char* out,
                            size_t len, const unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox){
    if(len == 0)
        return;

    size_t i;
    unsigned char user_key[KEY_SIZE];
//    unsigned char iv[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    memcpy(block_iv, in, BLOCK_SIZE);
    void* key;

    (*whiteBox) (block_iv, user_key, table);
    for(i = 0; i < VECTOR_SIZE; i++)
        user_key[i] ^= ivec[i];
    in += BLOCK_SIZE;

    key = malloc(type_size);
    (*set_key) (key, user_key);
    CRYPTO_cbc128_decrypt(in, out, len, key, block_iv, block);
    free(key);
}
