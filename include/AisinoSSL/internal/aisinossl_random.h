#ifndef HEADER_AISINOSSL_RANDOM_H
#define HEADER_AISINOSSL_RANDOM_H

/*
Random Module

Sample:
aisinossl_random_context ctx;
aisinossl_random_init(&ctx);
aisinossl_random_seed(&ctx, NULL, 0);
// ctx->drbg_ctx CAN BE USED TO hmac_drbg
aisinossl_random_rand_int_array(&ctx, arr, 30);
aisinossl_random_free(&ctx);

*/

#ifndef ANDROID_MK_VER
#include <AisinoSSL/aisinossl_config.h>
#endif

#ifdef _WIN32
#define _CRT_RAND_S
#endif
#include <stdlib.h>

#include <time.h>
#include <string.h>
#include <AisinoSSL/openssl/modes.h>
#include <AisinoSSL/mbedtls/md.h>
#include <AisinoSSL/mbedtls/hmac_drbg.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ANDROID_VER
#include <sys/system_properties.h>
#include <android/sensor.h>
#include <android/looper.h>
#endif

// Control HMAC-DRBG Hash Algorithm
// Attention! Use #define to set it
#ifndef RANDOM_HASH_ALGORITHM
#define RANDOM_HASH_ALGORITHM MD_SM3
#endif

// SET ANDROID SENSOR
// NOTE: https://developer.android.com/ndk/reference/group/sensor
//#define ENABLE_SEED_ANDROID_SENSOR
#define SEED_DEFAULT_SENSOR ASENSOR_TYPE_MAGNETIC_FIELD

// For Android test
//#define _DEBUG_

static unsigned int aisinoSSLRandomContextCount = 0;

// HMAC-DRBG Random Class
typedef struct {
    short isInitial;
    short isSeeded;

    unsigned char hashLen;
    unsigned char *hash;

    const mbedtls_md_info_t *md_info;     /*!<  Hash Type Info    */
    mbedtls_md_context_t *md_ctx;         /*!<  MD Context        */
    mbedtls_hmac_drbg_context *drbg_ctx;  /*!<  HMAC DRBG Context */
} aisinossl_random_context;

// Init Random Context
int aisinossl_random_init(aisinossl_random_context *ctx);

// Set or reset a seed
int aisinossl_random_seed(void* rand_ctx, unsigned char *seed_buf, size_t buf_size);
int aisinossl_random_seed_with_option(void *rand_ctx, unsigned char *seed_buf, size_t buf_size, int options);

// Rand a list of Number
int aisinossl_random_rand(void *rand_ctx, unsigned char *output, size_t size);

// Rand a list of int32
int aisinossl_random_rand_int_array(aisinossl_random_context *ctx, int *output, int count);

// Rand a list of Uint32
int aisinossl_random_rand_uint_array(aisinossl_random_context *ctx, unsigned int *output, int count);

// Release random context
void aisinossl_random_free(aisinossl_random_context *ctx);

// Shuffle unsigned char array
int aisinossl_random_shuffle_u8(u8 *list, int len);

// Rand a list of int32 (if ctx==NULL, then init a global ctx)
int aisinossl_random_list(aisinossl_random_context* ctx, int *list, int len);

// ERROR define
#define AISINOSSL_RANDOM_ERROR_HASH_ALGO_NOT_FOUND -0xF101
#define AISINOSSL_RANDOM_ERROR_NOT_INITIAL -0xF102
#define AISINOSSL_RANDOM_ERROR_NOT_SEEDED -0xF103
#define AISINOSSL_RANDOM_ERROR_OUT_SIZE_TO_LARGE -0xF104
#define AISINOSSL_RANDOM_ERROR_INVLIAD_SIZE -0xF105

// OPTION define
#define AISINOSSL_RANDOM_DISABLE_TIME 0x1
#define AISINOSSL_RANDOM_DISABLE_URANDOM 0x2
#define AISINOSSL_RANDOM_DISABLE_CPU_CYCLE 0x4
#define AISINOSSL_RANDOM_DISABLE_RAND_S 0x8
#define AISINOSSL_RANDOM_DISABLE_ANDROID_INFO 0x10
#define AISINOSSL_RANDOM_DISABLE_ANDROID_SENSOR 0x20

// OTHER define
#define AISINOSSL_RANDOM_MAX_BYTES_COUNT 1024
#define AISINOSSL_RANDOM_MAX_INT_COUNT (1024/4)

// ------ UTIL ------


// Deprecated: Old Random Function
int aisinossl_random_number(int upper);

#ifdef __cplusplus
}
#endif

#endif
