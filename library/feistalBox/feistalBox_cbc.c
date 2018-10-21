#include<feistalBox/feistalBox.h>
#include<wbc2/mode.h>
//size_t FEISTALBOX_cbc_encrypt(const unsigned char *in, unsigned char *out,
//                     size_t length, const FeistalBox *fb,
//                     unsigned char *ivec, const int enc, uint8_t wrap_flag){
//
//    if(enc == FEISTALBOX_ENC)
//        if(wrap_flag == WRAP_LEN){
//            return CRYPTO_cbc128_wrap_encrypt(in, out, length, fb, ivec, (block128_f)FEISTALBOX_encrypt);
//        }else{
//            CRYPTO_cbc128_encrypt(in, out, length, fb, ivec, (block128_f)FEISTALBOX_encrypt);
//            return length;
//        }
//    else if (enc == FEISTALBOX_DEC)
//    {
//        if (wrap_flag == WRAP_LEN)
//        {
//            return CRYPTO_cbc128_wrap_decrypt(in, out, length, fb, ivec, (block128_f)FEISTALBOX_decrypt);
//        }
//        else
//        {
//            CRYPTO_cbc128_decrypt(in, out, length, fb, ivec, (block128_f)FEISTALBOX_decrypt);
//            return length;
//        }
//    }
//    return 0;
//}