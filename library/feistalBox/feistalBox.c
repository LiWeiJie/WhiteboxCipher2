#include<feistalBox/feistalBox.h>
void FEISTALBOX_encrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundEnc(fb, in, out);
}

void FEISTALBOX_decrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundDec(fb, in, out);
}
