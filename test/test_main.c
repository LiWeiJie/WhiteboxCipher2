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
    
    printf("enc table size: %d\tp size: %d\n", fb_enc.tableSize, fb_enc.pSize);
    printf("dec table size: %d\tp size: %d\n", fb_dec.tableSize, fb_dec.pSize);

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
    free(buf);
    free(op);
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
    free(buf);
    free(op);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
//    int rounds = 10;
    wbc2NoAffine(key, ip, 5);
    wbc2NoAffine(key, ip, 50);
    wbc2NoAffine(key, ip, 500);
    printf("\n");
    wbc2WithAffine(key, ip, 5);
    wbc2WithAffine(key, ip, 50);
    wbc2WithAffine(key, ip, 500);
    printf("\n");
    return 0;
}

int import_test()
{
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    const uint8_t ip[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 100;
    printf("With Affine: %d rounds\n", rounds);
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;
    size_t size1 = 0;
    size_t size2 = 0;

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

    unsigned char* buf1 = FEISTALBOX_export_to_str(&fb_enc, &size1);
    unsigned char* buf2 = FEISTALBOX_export_to_str(&fb_dec, &size2);
    void* box1 = FEISTALBOX_import_from_str(buf1);
    void* box2 = FEISTALBOX_import_from_str(buf2);
    printf("Buf1 size:%ld\nBuf2 size:%ld\n", size1, size2);


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
    FILE* f1;
    FILE* f2;
    f1 = fopen("enc_table","wb");
    f2 = fopen("dec_table","wb");
    fwrite(buf1, sizeof(unsigned char), size1, f1);
    fwrite(buf2, sizeof(unsigned char), size2, f2);
    fclose(f1);
    fclose(f2);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    releaseFeistalBox(box1);
    releaseFeistalBox(box2);
    free(buf1);
    free(buf2);
    return 0;
}

int wcfb_example(){
    int rounds = 100;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    //const uint8_t ip[33] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char ip[1024];
    memset(ip, 0xff, 1024);
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
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
    buf = (uint8_t *)malloc(1024);
    op = (uint8_t *)malloc(1040);
    int num = 0;
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(ip, op, 1024, &fb_enc, &num, iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    num = 0;
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(op, buf, 1040, &fb_dec, &num, iv, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 1024);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    printf("\ninput:\n");
    dump(ip, 33);
    printf("\noutput:\n");
    dump(op, 49);
    printf("\nafter decode:\n");
    dump(buf, 33);
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
 }

int cbc_cfb_example(){
    int rounds = 10;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    const uint8_t ip[32] = { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    unsigned char iv2[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
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
    //uint8_t *op, *buf;
    //buf = (uint8_t *)malloc(32);
    //op = (uint8_t *)malloc(32);
    uint8_t op[32];
    uint8_t buf[32];
    int num = 0;
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_cfb_encrypt(ip, op, 32, &fb_enc, &num,iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    num = 0;
    ret = FEISTALBOX_cfb_encrypt(op, buf, 32, &fb_enc, &num,iv2, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 32);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    printf("\ninput:\n");
    dump(ip, 32);
    printf("\noutput:\n");
    dump(op, 32);
    printf("\nafter decode:\n");
    dump(buf, 32);
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
 }

int wcbc_example(){
    int rounds = 10;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    unsigned char ip[1024];
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    memset(ip, 0xff, 1024);
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
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
    buf = (uint8_t *)malloc(1024);
    op = (uint8_t *)malloc(1056);
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(ip, op, 1024, &fb_enc, iv, FEISTALBOX_ENC, WRAP_LEN);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(op, buf, 1056, &fb_dec, iv, FEISTALBOX_DEC,WRAP_LEN);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, 1024);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
 }

int main(int argv, char **argc) 
{
   // wbc2_example();
   // printf("wcbc test:\n");
   // wcbc_example();
    cbc_cfb_example();
   // printf("wcfb test:\n");
   //wcfb_example();
   // import_test();
    return 0;
}
