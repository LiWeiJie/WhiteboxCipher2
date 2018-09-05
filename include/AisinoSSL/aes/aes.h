/*
 * @Author: Weijie Li 
 * @Date: 2017-11-26 22:15:49 
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2017-11-26 22:20:51
 */
/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_AES_H
# define HEADER_AES_H

// # include <openssl/opensslconf.h>

# include <AisinoSSL/openssl/modes.h>
#ifndef ANDROID_MK_VER
#include <AisinoSSL/aisinossl_config.h>
#endif

# include <stddef.h>
# include <string.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define AES_ENCRYPT     1
# define AES_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
# define AES_MAXNR 14
# define AES_BLOCK_SIZE 16

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;
    
typedef GCM128_CONTEXT AES_GCM128_CONTEXT;

const char *AES_options(void);

/**
 * Expand the cipher key into the encryption key schedule.
 */
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

/**
 * Expand the cipher key into the decryption key schedule.
 */
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

/**
 AES encryption

 @param in data to be encrypt
 @param out encrypted data
 @param key AES's encrypt key
 */
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
    
/**
 AES decryption

 @param in data to be decrypt
 @param out decrypted data
 @param key AES's decrypt key
 */
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

    
/**
 AES ecb encrypt

 @param in data to be encrypt
 @param out encrypted data
 @param key AES's encrypt key
 @param enc 1 to AES_ENCRYPT, 0 to AES_DECRYPT
 */
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc);
    
/**
 AES cbc encrypt

 @param in data to be encrypt
 @param out encrypted data
 @param length length of in, in bytes
 @param key AES's encrypt key
 @param ivec iv
 @param enc 1 to AES_ENCRYPT, 0 to AES_DECRYPT
 */
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num);
/* NB: the IV is _two_ blocks long */
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        const AES_KEY *key2, const unsigned char *ivec,
                        const int enc);

/**
 AES_wrap_key

 @param key AES's encrypt key
 @param iv iv
 @param out output data
 @param in input data
 @param inlen bytes size of in
 @return 1 to successful, otherwises fault
 */
int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen);
    
/**
 AES_unwrap_key
 
 @param key AES's encrypt key
 @param iv iv
 @param out output data
 @param in input data
 @param inlen bytes size of in
 @return 1 to successful, otherwises fault
 */
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen);

    
/**
 AES_ctr128_encrypt
 
 The input encrypted as though 128bit counter mode is being used.  The
 extra state information to record how much of the 128bit block we have
 used is contained in *num, and the encrypted counter is kept in
 ecount_buf.  Both *num and ecount_buf must be initialised with zeros
 before the first call to AES_ctr128_encrypt(). This algorithm assumes
 that the counter is in the x lower bits of the IV (ivec), and that the
 application has full control over overflow and the rest of the IV.  This
 implementation takes NO responsibility for checking that the counter
 doesn't overflow into the rest of the IV when incremented.

 @param in data in
 @param out data out
 @param length byte size of in
 @param key key
 @param ivec iv
 @param ecount_buf extra state, must be initialised with zeros before the first call
 @param num extra state, must be initialised with zeros before the first call
 */
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key, unsigned char *ivec,
                        unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num);

//same as fucntion rfc3686_init
//4Bytes nounce + 8bytes iv + 4bytes counter
void AES_ctr128_ctr_init(unsigned char nonce[4], unsigned char iv[8], unsigned char ctr_buf[16]);

///* increment counter (128-bit int) by 1 */
void AES_ctr128_ctr_inc(unsigned char *counter);

/* decrement counter (128-bit int) by 1 */
void AES_ctr128_ctr_dec(unsigned char *counter);

void AES_ctr128_subctr(unsigned char *counter, const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key);

/**
 AES_gcm128_init

 @param ctx AES_GCM128_CONTEXT
 @param key key
 */
void AES_gcm128_init(AES_GCM128_CONTEXT *ctx, AES_KEY *key);
    
/**
 AES_gcm128_setiv

 @param ctx AES_GCM128_CONTEXT
 @param ivec iv
 @param len byte size of iv
 */
void AES_gcm128_setiv(AES_GCM128_CONTEXT *ctx, const unsigned char *ivec,
                      size_t len);
    
/**
 addition message of gcm

 @param ctx AES_GCM128_CONTEXT
 @param aad addition message
 @param len byte size of aad
 @return 1 to successful, otherwises fault
 */
int AES_gcm128_aad(AES_GCM128_CONTEXT *ctx, const unsigned char *aad,
                    size_t len);

/**
 AES_gcm128_encrypt

 @param in in
 @param out out
 @param length byte size of in
 @param ctx AES_GCM128_CONTEXT
 @param enc 1 to AES_ENCRYPT, 0 to AES_DECRYPT
 @return 1 to successful, otherwises fault
 */
int AES_gcm128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, AES_GCM128_CONTEXT *ctx, const int enc);

/**
 get tag of AES_gcm128

 @param ctx AES_GCM128_CONTEXT
 @param tag memory for storage tag
 @param len byte size of tag
 */
void AES_gcm128_tag(AES_GCM128_CONTEXT *ctx, unsigned char *tag,
                    size_t len);

/**
 AES_gcm128_finish

 @param ctx AES_GCM128_CONTEXT
 @param tag memory for storage tag
 @param len byte size of tag
 @return 1 to successful, otherwises fault
 */
int AES_gcm128_finish(AES_GCM128_CONTEXT *ctx, const unsigned char *tag,
                      size_t len);


/**
 release AES_GCM128_CONTEXT

 @param ctx AES_GCM128_CONTEXT
 */
void AES_gcm128_release(AES_GCM128_CONTEXT *ctx);



/**
 * aes gcm file context
 */
typedef gcmf_context aes_gcmf_context;

// stop support gcm for file of aes
// to check the aes_key->rounds after gcmf_set_key(ctx, &aes_key, (block128_f)AES_encrypt)
// in function int aes_gcmf_set_key(aes_gcmf_context *ctx, const unsigned char * key,size_t len);
// in file aes_gcmf.c

/**
 * init the aes gcm file context
 *
 * @param  ctx [in]		gcm file context
 * 
 * @param  aes_key [in]		aes key
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int aes_gcmf_init(aes_gcmf_context *ctx, const AES_KEY *aes_key);

/**
 * gcm file context free
 *
 * @param  ctx [in]		gcm file context
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int aes_gcmf_free(aes_gcmf_context *ctx);

/**
 * set aes iv param
 *
 * @param  ctx [in]		gcm file context
 *
 * @param  iv  [iv]		iv array
 *
 * @param  len [in]		iv array length
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int aes_gcmf_set_iv(aes_gcmf_context *ctx, const unsigned char * iv, size_t len);

/**
 * encrypte file
 *
 * @param  ctx      [in]		gcm file context
 *
 * @param  infpath  [in]		plaintext file input path
 *
 * @param  outfpath [in]		cipher file output path
 *
 * @return          [fage]		if successful o,otherwise failed
 */
int aes_gcmf_encrypt_file(aes_gcmf_context * ctx, char *infpath, char *outfpath);

/**
 * decrypt file
 *
 * @param  ctx      [in]		gcm file context
 *
 * @param  infpath  [in]		cipher file input path
 *
 * @param  outfpath [in]		plaintext file output path
 *
 * @return          [flag]		if successful o,otherwise failed
 */
int aes_gcmf_decrypt_file(aes_gcmf_context * ctx, char *infpath, char *outfpath);

# ifdef  __cplusplus
}
# endif

#endif
