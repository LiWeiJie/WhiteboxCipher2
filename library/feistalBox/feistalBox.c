#include<feistalBox/feistalBox.h>
void FEISTALBOX_encrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundEnc(fb, in, out);
}

void FEISTALBOX_decrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundDnc(fb, in, out);

}

void FEISTALBOX_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t length, const FeistalBox *fb,
                            unsigned char *ivec, const int enc)
{
    if (enc == FEISTALBOX_DEC)
    {
        CRYPTO_cbc128_encrypt(in, out, length, fb, ivec,
                              (block128_f)FEISTALBOX_encrypt);
    }
    else
    {
        CRYPTO_cbc128_encrypt(in, out, length, fb, ivec,
                              (block128_f)FEISTALBOX_decrypt);
    }
}

void FEISTALBOX_cfb_encrypt(const unsigned char *in, unsigned char *out,
                            size_t length, const FeistalBox *fb,
                            unsigned char *ivec, const int enc)
{
    if (enc == FEISTALBOX_DEC)
    {
        CRYPTO_cfb128_encrypt(in, out, length, fb, ivec,
                              (block128_f)FEISTALBOX_encrypt);
    }
    else
    {
        CRYPTO_cfb128_encrypt(in, out, length, fb, ivec,
                              (block128_f)FEISTALBOX_decrypt);
    }
}