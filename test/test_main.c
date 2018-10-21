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

#include "count_cycles.h"

int wbc2WithAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    // const uint8_t key[16] = { 0 };
    printf("With Affine: %d rounds\n", rounds);
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;

    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(&fb_enc, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(&fb_dec, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret==0?"√":"✘");
    if (ret != 0){
        dump(ip,16);
        dump(op,16);
        dump(buf, 16);
    }
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wbc2NoAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    printf("No Affine: %d rounds\n", rounds);
    // const uint8_t key[16] = { 0 };
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;

    set_time_start();
    ret = initFeistalBoxConfigNoAffine(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfigNoAffine Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(&fb_enc, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(&fb_dec, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret==0?"√":"✘");
    if (ret != 0){
        dump(ip,16);
        dump(op,16);
        dump(buf, 16);
    }
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 10;
    wbc2NoAffine(key, ip, 10);
    wbc2NoAffine(key, ip, 100);
    wbc2NoAffine(key, ip, 1000);
    printf("\n");
    wbc2WithAffine(key, ip, 10);
    wbc2WithAffine(key, ip, 100);
    wbc2WithAffine(key, ip, 1000);
    printf("\n");
    return 0;
}

int import_test()
{
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    const uint8_t ip[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 10;
    printf("With Affine: %d rounds\n", rounds);
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;

    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    unsigned char* buf1 = FEISTALBOX_export_to_str(&fb_enc);
    unsigned char* buf2 = FEISTALBOX_export_to_str(&fb_dec);
    FeistalBox* box1 = FEISTALBOX_import_from_str(buf1);
    FeistalBox* box2 = FEISTALBOX_import_from_str(buf2);


    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t *)malloc(16);
    op = (uint8_t *)malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(box1, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(box2, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    dump(ip, 16);
    dump(op, 16);
    dump(buf, 16);
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    releaseFeistalBox(box1);
    releaseFeistalBox(box2);
    free(buf1);
    free(buf2);
    return 0;
}

// int wcbc_example(){
//     int rounds = 2;
//     const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
//     const uint8_t ip[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
//     const unsigned char iv[16] = { 0x11,0x14,0x16,0x18,0x1a,0x1c,0xde,0xf0,0x12,0x37,0x56,0x75,0x94,0xb3,0xd2,0xf1};

//     FeistalBox fb;
//     //initFeistalBox(FeistalBox_SM4_128_128, &fb);
//     initFeistalBoxNoAffine(FeistalBox_SM4_128_128, &fb);
//     int len = generateFeistalBox(key, 1, 15, rounds, &fb);
//     // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
//     printf("%d\n", len);
//     // dump(fb.table, len);
//     uint8_t *op, *buf;
//     buf = (uint8_t*) malloc(48);
//     op = (uint8_t*) malloc(48);
//     printf("input:\n");
//     dump(ip, 32);
//     FEISTALBOX_wcbc_encrypt(ip, op, 32, &fb, iv, FEISTALBOX_ENC);
//     printf("output:\n");
//     dump(op, 48);
//     FEISTALBOX_wcbc_encrypt(op, buf, 32, &fb, iv, FEISTALBOX_DEC);
//     printf("after decode:\n");
//     dump(buf, 48);
//     releaseFeistalBox(&fb);
//     return 0;
// }

int main(int argv, char **argc) 
{
    //wbc2_example();
    // wcbc_example();
    import_test();
    return 0;
}