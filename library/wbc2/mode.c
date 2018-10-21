#include "AisinoSSL/internal/aisinossl_random.h"
#include "wbc2/mode.h"
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

void set_message_block(unsigned char* message_block, size_t* len){
    memcpy(message_block, len, VECTOR_SIZE/2);
    message_block += VECTOR_SIZE/2;
    memset(message_block, 0, VECTOR_SIZE/2);
}


size_t CRYPTO_wcbc128_encrypt(const unsigned char* in, unsigned char* out,
                            size_t len, unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size,
                            const void* table, whiteBox_block128_f whiteBox, uint8_t wrap_flag){
    if (len == 0)
        return 0;

    size_t i;
    size_t message_length;
    unsigned char user_key[KEY_SIZE];
    unsigned char iv[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    unsigned char message_block[VECTOR_SIZE];
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

    /* get length after padding */
    message_length = (len % 16 == 0)? len : len + BLOCK_SIZE - (len % 16) ;
    
    if(wrap_flag == NOT_WRAP_LEN){
        free(key);
        return BLOCK_SIZE + message_length;
    }


    /* get last block*/
    out = out + message_length - BLOCK_SIZE;
    memcpy(block_iv, out, VECTOR_SIZE);
    out += BLOCK_SIZE;
    set_message_block(message_block, &len);
    for(i = 0;i<VECTOR_SIZE;i++){
        block_iv[i] ^= message_block[i];
    }

    (*block) (block_iv, out, key);
    free(key);

    /* return the output length*/
    return message_length + 2 * BLOCK_SIZE;

}

size_t CRYPTO_wcbc128_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, unsigned char ivec[16],
                            block128_f block, set_key_f set_key, size_t type_size,
                            const void *table, whiteBox_block128_f whiteBox, uint8_t wrap_flag)
{
    /* at least one block*/
    if (len <= BLOCK_SIZE)
        return 0;

    size_t i;
    size_t message_length;
    unsigned char user_key[KEY_SIZE];
//    unsigned char iv[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    memcpy(block_iv, in, BLOCK_SIZE);
    void *key;

    (*whiteBox)(block_iv, user_key, table);
    for (i = 0; i < VECTOR_SIZE; i++)
        user_key[i] ^= ivec[i];
    in += BLOCK_SIZE;

    key = malloc(type_size);
    (*set_key)(key, user_key);
    len -= BLOCK_SIZE;

    CRYPTO_cbc128_decrypt(in, out, len, key, block_iv, block);
    free(key);

    if(wrap_flag == NOT_WRAP_LEN){
        return len - BLOCK_SIZE;
    }
    /*get last block*/
    out = out + len - BLOCK_SIZE;
    memcpy(&message_length, out, VECTOR_SIZE/2);
    return message_length;
}

size_t CRYPTO_wcfb128_encrypt(const unsigned char *in, unsigned char *out,
                              size_t len, unsigned char ivec[16],
                              block128_f block, set_key_f set_key, size_t type_size, int* num,
                              const void *table, whiteBox_block128_f whiteBox){
    if (len == 0)
        return 0;

    size_t i;
    unsigned char user_key[KEY_SIZE];
    unsigned char tmp[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    void* key;

    gen_one_time_userkey(user_key, KEY_SIZE);
    memcpy(tmp, ivec, VECTOR_SIZE);
    for(i = 0; i < VECTOR_SIZE; i++)
        block_iv[i] = tmp[i] ^ user_key[i];
    (*whiteBox) (block_iv, tmp, table);

    memcpy(out, tmp, VECTOR_SIZE);
    out += BLOCK_SIZE;

    key = malloc(type_size);
    (*set_key) (key, user_key);
    CRYPTO_cfb128_encrypt(in, out, len, key, block_iv, num, ENC, block);

    free(key);
    return len + BLOCK_SIZE;
    
}

size_t CRYPTO_wcfb128_decrypt(const unsigned char* in, unsigned char* out,
                            size_t len, unsigned char ivec[16],
                            block128_f block,set_key_f set_key, size_t type_size, int* num,
                            const void* table, whiteBox_block128_f whiteBox){
    /* at least one block*/
    if (len <= BLOCK_SIZE)
        return 0;

    size_t i;
    unsigned char user_key[KEY_SIZE];
    unsigned char tmp[VECTOR_SIZE];
    unsigned char block_iv[VECTOR_SIZE];
    memcpy(tmp, in, BLOCK_SIZE);
    void *key;

    (*whiteBox)(tmp, block_iv, table);
    for (i = 0; i < VECTOR_SIZE; i++)
        user_key[i] = ivec[i] ^ block_iv[i];
    in += BLOCK_SIZE;

    key = malloc(type_size);
    (*set_key)(key, user_key);
    len -= BLOCK_SIZE;

    CRYPTO_cfb128_encrypt(in, out, len, key, block_iv, num, DEC, block);
    free(key);

    return len;
    /*get last block*/
}

////TODO:debugging
//size_t CRYPTO_cbc128_wrap_encrypt(const unsigned char *in, unsigned char *out,
//                                  size_t len, const void *key,
//                                  unsigned char ivec[16], block128_f block){
//    size_t message_length;
//    size_t i;
//    unsigned char message_block[VECTOR_SIZE];
//    unsigned char block_iv[VECTOR_SIZE];
//    CRYPTO_cbc128_encrypt(in, out, len, key, ivec, block);
//
//    message_length = (len % 16 == 0)? len : len + BLOCK_SIZE - (len % 16) ;
//
//    out = out + message_length - BLOCK_SIZE;
//    memcpy(block_iv, out, VECTOR_SIZE);
//    out += BLOCK_SIZE;
//    set_message_block(message_block, &len);
//    for(i = 0;i<VECTOR_SIZE;i++){
//        block_iv[i] ^= message_block[i];
//    }
//
//    (*block) (block_iv, out, key);
//
//    /* return the output length*/
//    return message_length +  BLOCK_SIZE;
//
//
//}
//
//size_t CRYPTO_cbc128_wrap_decrypt(const unsigned char *in, unsigned char *out,
//                                  size_t len, const void *key,
//                                  unsigned char ivec[16], block128_f block){
//    CRYPTO_cbc128_decrypt(in, out, len, key, ivec, block);
//    size_t message_length;
//    out = out + len - BLOCK_SIZE;
//    memcpy(&message_length, out, VECTOR_SIZE/2);
//    return message_length;
//}
