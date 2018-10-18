#include <stdio.h>
#include <feistalBox/feistalBox.h>
#include <wbc2/wbc2.h>

void dump(const uint8_t * li, int len) {
    int line_ctrl = 16;
    for (int i=0; i<len; i++) {
        printf("%02X", (*li++));
        if ((i+1)%line_ctrl==0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
}

int wbc2WithAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    // const uint8_t key[16] = { 0 };
    printf("With Affine\n");
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    int len = generateFeistalBox(&cfg, eFeistalBoxEnc, &fb_enc);
    printf("%d\n", len);
    len = generateFeistalBox(&cfg, eFeistalBoxDec, &fb_dec);
    printf("%d\n", len);
    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    dump(ip, 16);
    feistalRoundEnc(&fb_enc, ip, op);
    dump(op, 16);
    feistalRoundDec(&fb_dec, op, buf);
    dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wbc2NoAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    printf("No Affine\n");
    // const uint8_t key[16] = { 0 };
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    initFeistalBoxConfigNoAffine(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    int len = generateFeistalBox(&cfg, eFeistalBoxEnc, &fb_enc);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", len);
    len = generateFeistalBox(&cfg, eFeistalBoxDec, &fb_dec);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", len);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    dump(ip, 16);
    feistalRoundEnc(&fb_enc, ip, op);
    dump(op, 16);
    feistalRoundDec(&fb_dec, op, buf);
    dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 10;
    wbc2NoAffine(key, ip, rounds);
    wbc2WithAffine(key, ip, rounds);
    return 0;
}

int wcbc_example(){
    int rounds = 2;
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    const unsigned char iv[16] = { 0x11,0x14,0x16,0x18,0x1a,0x1c,0xde,0xf0,0x12,0x37,0x56,0x75,0x94,0xb3,0xd2,0xf1};

    FeistalBox fb;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    initFeistalBoxNoAffine(FeistalBox_SM4_128_128, &fb);
    int len = generateFeistalBox(key, 1, 15, rounds, &fb);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", len);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(48);
    op = (uint8_t*) malloc(48);
    printf("input:\n");
    dump(ip, 32);
    FEISTALBOX_wcbc_encrypt(ip, op, 32, &fb, iv, FEISTALBOX_ENC);
    printf("output:\n");
    dump(op, 48);
    FEISTALBOX_wcbc_encrypt(op, buf, 32, &fb, iv, FEISTALBOX_DEC);
    printf("after decode:\n");
    dump(buf, 48);
    releaseFeistalBox(&fb);
    return 0;
}

int main(int argv, char **argc) 
{
    wbc2_example();
    wcbc_example();
    return 0;
}