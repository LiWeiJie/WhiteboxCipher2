#include<feistalBox/feistalBox.h>
#include<AisinoSSL/sm4/sm4.h>
#include<wbc2/mode.h>


size_t FEISTALBOX_wcfb_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb, int* num ,
                     unsigned char *ivec, const int enc, uint8_t wrap_flag){
    if(enc == FEISTALBOX_ENC)
        return CRYPTO_wcfb128_encrypt(in, out, length, ivec, (block128_f)sm4_encrypt, (set_key_f)sm4_set_encrypt_key, sizeof(sm4_key_t), num, fb,  (whiteBox_block128_f) FEISTALBOX_encrypt, wrap_flag);
    else if (enc == FEISTALBOX_DEC)
        return CRYPTO_wcfb128_decrypt(in, out, length, ivec, (block128_f)sm4_encrypt, (set_key_f)sm4_set_encrypt_key, sizeof(sm4_key_t), num, fb,  (whiteBox_block128_f) FEISTALBOX_decrypt, wrap_flag);
    return 0;
}