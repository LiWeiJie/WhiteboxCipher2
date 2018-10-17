#include<feistalBox/feistalBox.h>
#include<AisinoSSL/sm4/sm4.h>
#include<wbc2/mode.h>


void FEISTALBOX_wcbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     const unsigned char *ivec, const int enc){
    if(enc == FEISTALBOX_ENC)
        CRYPTO_wcbc128_encrypt(in, out, length, ivec, (block128_f)sm4_encrypt, (set_key_f)sm4_set_encrypt_key, sizeof(sm4_key_t), fb, (whiteBox_block128_f) FEISTALBOX_encrypt);
    else if (enc == FEISTALBOX_DEC)
        CRYPTO_wcbc128_decrypt(in, out, length, ivec, (block128_f)sm4_encrypt, (set_key_f)sm4_set_decrypt_key, sizeof(sm4_key_t), fb, (whiteBox_block128_f) FEISTALBOX_decrypt);
        
}