#ifndef HEADER_FEISTALBOX_H
#define HEADER_FEISTALBOX_H

#include<wbc2.h>
#include<AisinoSSL/openssl/modes.h>
#define FEISTALBOX_ENC 0
#define FEISTALBOX_DEC 1

# ifdef  __cplusplus
extern "C" {
# endif


/**
 FeistalBox cbc encrypt

 @param in data to be encrypt
 @param out encrypted data
 @param length length of in, in bytes
 @param key FeistalBox's encrypt key
 @param ivec iv
 @param enc 1 to FEISTALBOX_ENC, 0 to FEISTALBOX_DEC
 */

void FEISTALBOX_encrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb);
void FEISTALBOX_decrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb);

void FEISTALBOX_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     unsigned char *ivec, const int enc);


void FEISTALBOX_cfb_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     unsigned char *ivec, const int enc);

# ifdef  __cplusplus
}
# endif

#endif