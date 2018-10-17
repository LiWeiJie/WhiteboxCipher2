#include <stdio.h>

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
    feistalRoundEnc(&fb, ip, op);
    dump(op, 16);
    feistalRoundDec(&fb, op, buf);
    dump(buf, 16);
    releaseFeistalBox(&fb);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int rounds = 2;
    wbc2NoAffine(key, ip, rounds);
    wbc2WithAffine(key, ip, rounds);
    return 0;
}

int main(int argv, char **argc) 
{
    wbc2_example();
    return 0;
}