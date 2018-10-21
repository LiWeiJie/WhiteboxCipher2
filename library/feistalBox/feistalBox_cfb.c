#include<feistalBox/feistalBox.h>
#include<wbc2/mode.h>
size_t FEISTALBOX_cfb_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const FeistalBox *fb, int* num,
                     unsigned char *ivec, const int enc, uint8_t wrap_flag){

    if (enc == FEISTALBOX_ENC)
    {
        CRYPTO_cfb128_encrypt(in, out, length, fb, ivec, num, ENC, (block128_f)feistalRoundEnc);
        return length;
    }
    else if (enc == FEISTALBOX_DEC)
    {
        CRYPTO_cfb128_encrypt(in, out, length, fb, ivec, num, DEC, (block128_f)feistalRoundEnc);
        return length;
    }
    return 0;
}