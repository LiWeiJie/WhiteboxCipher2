#include<feistalBox/feistalBox.h>
#include<wbc2/mode.h>
size_t FEISTALBOX_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb,
                     unsigned char *ivec, const int enc){

    if (enc == FEISTALBOX_ENC)
    {
        CRYPTO_cbc128_encrypt(in, out, length, fb, ivec,  (block128_f)FEISTALBOX_encrypt);
        return length;
    }
    else if (enc == FEISTALBOX_DEC)
    {
        CRYPTO_cbc128_decrypt(in, out, length, fb, ivec,  (block128_f)FEISTALBOX_decrypt);
        return length;
    }
    return 0;
}