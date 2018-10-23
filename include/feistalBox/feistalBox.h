#ifndef HEADER_FEISTALBOX_H
#define HEADER_FEISTALBOX_H

#include<wbc2/wbc2.h>
#include<AisinoSSL/openssl/modes.h>
#include<stdio.h>
#include<stdlib.h>
#define FEISTALBOX_ENC 1
#define FEISTALBOX_DEC 0
#define WRAP_LEN 0
#define NOT_WRAP_LEN 1

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
 @param wrap_flag 0 to WRAP_LEN, 1 to NOT_WRAP_LEN; For controlling whether wrap the message length at last cipher block 
 
 return the length of output
 in WRAP_LEN it will return: ceiling(input_length) + 2 * block_size   
 else it return:ceiling(input_length) + block_size
 actually in this case block_size equal 16bytes
 */


/* key generation define in wbc2.h */
void FEISTALBOX_encrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb);
void FEISTALBOX_decrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb);

/**
 FeistalBox wcbc encrypt

 @param in data to be encrypt
 @param out encrypted data
 @param length length of in, in bytes
 @param key FeistalBox's encrypt key
 @param ivec iv
 @param enc 1 to FEISTALBOX_ENC, 0 to FEISTALBOX_DEC
 @param wrap_flag 0 to WRAP_LEN, 1 to NOT_WRAP_LEN; For controlling whether wrap the message length at last cipher block 
 
 return the length of output
 in WRAP_LEN it will return: ceiling(input_length) + 2 * block_size   
 else it return:ceiling(input_length) + block_size
 actually in this case block_size equal 16bytes
 */
size_t FEISTALBOX_wcbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     unsigned char *ivec, const int enc, uint8_t wrap_flag);

/**
 FeistalBox wcfb encrypt

 @param in data to be encrypt
 @param out encrypted data
 @param length length of in, in bytes
 @param key FeistalBox's encrypt key
 @param ivec iv
 @param enc 1 to FEISTALBOX_ENC, 0 to FEISTALBOX_DEC
 
 attention: No wrap length!
 return the length of output,indeed equal to the input length

 */
size_t FEISTALBOX_wcfb_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb, int* num,
                     unsigned char *ivec, const int enc);

size_t FEISTALBOX_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     unsigned char *ivec, const int enc);

size_t FEISTALBOX_cfb_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb, int* num,
                     unsigned char *ivec, const int enc);

FeistalBox* FEISTALBOX_import_from_str(void* src);

/* return the pointer of string and return the size at sz*/
void* FEISTALBOX_export_to_str(const FeistalBox* fb, size_t* sz);


# ifdef  __cplusplus
}
# endif

#endif