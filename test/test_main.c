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
    FeistalBox fb;
    initFeistalBox(FeistalBox_SM4_128_128, &fb);
    int len = generateFeistalBox(key, 1, 15, rounds, &fb);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", len);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    dump(ip, 16);
    feistalRoundEnc(&fb, ip, op);
    dump(op, 16);
    feistalRoundDec(&fb, op, buf);
    dump(buf, 16);
    releaseFeistalBox(&fb);
    return 0;
}

int wbc2NoAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    // const uint8_t key[16] = { 0 };
    FeistalBox fb;
    initFeistalBoxNoAffine(FeistalBox_SM4_128_128, &fb);
    int len = generateFeistalBox(key, 1, 15, rounds, &fb);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", len);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    dump(ip, 16);
    FEISTALBOX_encrypt(ip, op, &fb);
    dump(op, 16);
    FEISTALBOX_decrypt(op, buf, &fb);
    dump(buf, 16);
    releaseFeistalBox(&fb);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 100;
    wbc2NoAffine(key, ip, rounds);
    wbc2WithAffine(key, ip, rounds);
    return 0;
}


int wcbc_example(){
    int rounds = 100;
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[33] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char iv[16] = { 0x11,0x14,0x16,0x18,0x1a,0x1c,0xde,0xf0,0x12,0x37,0x56,0x75,0x94,0xb3,0xd2,0xf1};
    size_t len;
    FeistalBox fb;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    initFeistalBoxNoAffine(FeistalBox_SM4_128_128, &fb);
    int res = generateFeistalBox(key, 1, 15, rounds, &fb);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", res);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(80);
    op = (uint8_t*) malloc(80);
    printf("input:\n");
    dump(ip, 33);
    len = FEISTALBOX_wcbc_encrypt(ip, op, 33, &fb, iv, FEISTALBOX_ENC, NOT_WRAP_LEN);
    printf("output:\n");
    printf("len:%d\n", len);
    dump(op, 80);
    len = FEISTALBOX_wcbc_encrypt(op, buf, 80, &fb, iv, FEISTALBOX_DEC, NOT_WRAP_LEN);
    printf("after decode:\n");
    printf("len:%d\n", len);
    dump(buf, 48);
    releaseFeistalBox(&fb);
    free(op);
    free(buf);
    return 0;
}

int wcfb_example(){
    int rounds = 100;
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[33] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char iv[16] = { 0x11,0x14,0x16,0x18,0x1a,0x1c,0xde,0xf0,0x12,0x37,0x56,0x75,0x94,0xb3,0xd2,0xf1};
    size_t len;
    int counter;
    FeistalBox fb;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    initFeistalBoxNoAffine(FeistalBox_SM4_128_128, &fb);
    int res = generateFeistalBox(key, 1, 15, rounds, &fb);
    // len = generateFeistalBox(key, 1, 15, FEISTAL_ROUNDS, &fb);
    printf("%d\n", res);
    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(49);
    op = (uint8_t*) malloc(49);
    printf("input:\n");
    dump(ip, 33);
    counter = 0;
    len = FEISTALBOX_wcfb_encrypt(ip, op, 33, &fb, &counter, iv, FEISTALBOX_ENC, WRAP_LEN);
    printf("len:%d\n", len);
    printf("output:\n");
    dump(op, 64);
    counter = 0;
    len = FEISTALBOX_wcfb_encrypt(op, buf, 49, &fb, &counter, iv, FEISTALBOX_DEC, WRAP_LEN);
    printf("after decode:\n");
    printf("len:%d\n", len);
    dump(buf, 64);
    releaseFeistalBox(&fb);
    free(op);
    free(buf);
    return 0;
}
int main(int argv, char **argc) 
{
    printf("wbc2 test:\n");
    wbc2_example();
    printf("wcbc test:\n");
    wcbc_example();
    printf("wcfb test:\n");
    wcfb_example();
    return 0;
}