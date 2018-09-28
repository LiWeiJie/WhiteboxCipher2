#include <stdio.h>

#include <wbc2/wbc2.h>

void dump(uint8_t * li, int len) {
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

int main(int argv, char **argc) 
{
    const uint8_t key[16] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    FeistalBox fb;
    initFeistalBox(FeistalBox_SM4_128_128, &fb);
    int len = generateFeistalBox(key, 1, 15, &fb);
    printf("%d\n", len);
    dump(fb.table, len);
    releaseFeistalBox(&fb);
    return 0;
}