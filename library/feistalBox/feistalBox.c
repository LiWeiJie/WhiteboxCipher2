#include<feistalBox/feistalBox.h>
#define LAYER_SIZE 4096
#define ENCODE_SIZE 4096
#define POINTER_SIZE sizeof(unsigned char*)
void FEISTALBOX_encrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundEnc(fb, in, out);
}

void FEISTALBOX_decrypt(const unsigned char *in, unsigned char *out, const FeistalBox *fb){
     feistalRoundDec(fb, in, out);
}


/* allocate memory for store string ,remember to free this one */
void* FEISTALBOX_export_to_str(const FeistalBox* fb){
    /* calculate size and allocate memory */
    const int _ob = fb->outputBytes;
    const int _ib = fb->inputBytes;
    const int rounds = fb->rounds;
    uint64_t upper = ((uint64_t)1<<(8*_ib));
    const uint64_t table_size = upper * rounds * _ob;
    const uint64_t p_size = rounds * LAYER_SIZE * sizeof(uint8_t);
    size_t size = sizeof(enum FeistalBoxAlgo) + sizeof(enum E_FeistalBoxEncMode) +  sizeof(int) * 6   + table_size   + p_size + ENCODE_SIZE * 2;
    void* result = malloc(size);

    unsigned char* iter = result;

    if(iter == NULL )
        return NULL;

    /* copy the rest data */ 
    memcpy(iter, fb, sizeof(FeistalBox) - 2 * POINTER_SIZE);
    iter = iter +  sizeof(FeistalBox) - 2 * POINTER_SIZE;


    /* copy table memory */
    memcpy(iter, fb->table, table_size);
    iter += table_size;

    /* copy p_table memory */
    memcpy(iter, fb->p, p_size);
    iter += p_size;



    return result;
}

FeistalBox* FEISTALBOX_import_from_str(void* src){
    FeistalBox* result = malloc(sizeof(FeistalBox));
    unsigned char* tmp = src;

    /* copy the data except table and p_table */
    memcpy(result, tmp, sizeof(FeistalBox) - 2 * POINTER_SIZE);
    tmp += sizeof(FeistalBox) - 2 * POINTER_SIZE;

    /* calculate table size*/
    const int _ob = result->outputBytes;
    const int _ib = result->inputBytes;
    const int rounds = result->rounds;
    uint64_t upper = ((uint64_t)1<<(8*_ib));
    const uint64_t table_size = upper * rounds * _ob;
    const uint64_t p_size = rounds * LAYER_SIZE * sizeof(uint8_t);

    void* table = malloc(table_size);
    void* p = malloc(p_size);

    /* copy table data*/
    memcpy(table, tmp, table_size);
    tmp += table_size;

    memcpy(p, tmp, p_size);
    tmp += p_size;

    result->table = table;
    result->p = p;

    return result;
}