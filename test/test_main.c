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

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    // const uint8_t key[16] = { 0 };
    FeistalBox fb;
    initFeistalBox(FeistalBox_SM4_128_128, &fb);
    int len = generateFeistalBox(key, 1, 15, &fb);
    printf("%d\n", len);
    // dump(fb.table, len);
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    dump(ip, 16);
    feistalRoundEnc(&fb, ip, FEISTAL_ROUNDS, op);
    dump(op, 16);
    feistalRoundDec(&fb, op, FEISTAL_ROUNDS, buf);
    dump(buf, 16);
    releaseFeistalBox(&fb);
    return 0;
}

int main(int argv, char **argc) 
{
    wbc2_example();
    return 0;
}