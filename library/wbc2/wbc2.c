/**
 * @brief 
 * 
 * @file wbc2.c
 * @author liweijie
 * @date 2018-09-05
 */

#include <assert.h>
// #include <machine/endian.h>

#include "wbc2/wbc2.h"
#include <AisinoSSL/sm4/sm4.h>

#ifdef WIN32
#include <winsock.h>
#endif

static void dump(const uint8_t * li, int len) {
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

int initFeistalBox(enum FeistalBoxAlgo algo, FeistalBox *box) 
{
    switch (algo) {
        case FeistalBox_AES_128_128:
            box->algo = algo;
            box->blockBytes = 16;
            box->inputBytes = 0;
            box->outputBytes = 0;
            box->table = 0;
            break;
        case FeistalBox_SM4_128_128:
            box->algo = algo;
            box->blockBytes = 16;
            box->inputBytes = 0;
            box->outputBytes = 0;
            box->table = 0;
            break;
        default:
            return FEISTAL_BOX_INVALID_ALGO;
            break;
    }
    return 0;
}

int releaseFeistalBox(FeistalBox *box)
{
    if (!box->table) {
        free(box->table);
        box->table = 0;
    }
    return 0;
}

// 0: all fine, otherwise error code
int checkFeistalBox(const FeistalBox *box)
{
    // step 1. check algo
    if (box->algo<1 || box->algo > FEISTAL_ALGOS_NUM)
        return FEISTAL_BOX_INVALID_BOX;
    // step 2. check block bytes
    if (box->blockBytes != 16) {
        return FEISTAL_BOX_INVALID_BOX;
    }
    return 0;
}

uint32_t swap32(uint32_t num) 
{
    return ((num>>24)&0xff) | // move byte 3 to byte 0
                    ((num<<8)&0xff0000) | // move byte 1 to byte 2
                    ((num>>8)&0xff00) | // move byte 2 to byte 1
                    ((num<<24)&0xff000000);
}

#define m_htole32(p) swap32(htons(p))


//return sizeof box
int generateFeistalBox(const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBox *box)
{
    int ret = 0;
    if (rounds<1)
        return ret = FEISTAL_ROUND_NULL_ROUND_TOO_SMALL;
    if (rounds>FEISTA_MAX_ROUNDS)
        return ret = FEISTAL_ROUND_NULL_ROUND_TOO_BIG;

    assert(inputBytes <= 4);
    if (inputBytes > 4)
        return ret = FEISTAL_BOX_NOT_IMPLEMENT;

    assert(outputBytes <= box->blockBytes);
    if (outputBytes > box->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;

    assert(inputBytes+outputBytes == box->blockBytes);
    if (inputBytes+outputBytes != box->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;
    
    box->inputBytes = inputBytes;
    box->rounds = rounds;
    box->outputBytes = outputBytes;
    uint8_t *plaintext;
    enum FeistalBoxAlgo algo = box->algo;

    if ((ret = checkFeistalBox(box)))
        return ret;

    switch (algo) {
        case FeistalBox_AES_128_128:
        {
            //aes
            uint64_t upper = ((long long)1<<(8*inputBytes));
            int blockBytes = box->blockBytes;
            box->table = malloc(outputBytes*upper);
            box->tableSize = outputBytes*upper;
            uint8_t* box_table = box->table;

            AES_KEY aes_key;
            AES_set_encrypt_key(key, 128, &aes_key);

            plaintext = (uint8_t *)calloc(blockBytes, sizeof(uint8_t));
            if(!plaintext)
                return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
            
            uint8_t buffer[blockBytes];
            uint32_t p = 0;

            uint8_t * dst = box_table;
            while(p<upper) {
                uint32_t t = m_htole32(p);
                *(uint32_t*) plaintext = t;
                AES_encrypt(plaintext, buffer, &aes_key);
                memcpy(dst, buffer, outputBytes);
                dst += outputBytes;
                ++p;
            }
            free(plaintext);
            return dst-box_table;
            break;
        }
        case FeistalBox_SM4_128_128:
        {
            //sm4
            uint64_t upper = ((long long)1<<(8*inputBytes));
            // alias the variables
            int blockBytes = box->blockBytes;
            box->table = malloc(outputBytes*upper);
            box->tableSize = outputBytes*upper;
            uint8_t* box_table = box->table;
            // step 1. set key
            struct sm4_key_t sm4_key;
            sm4_set_encrypt_key(&sm4_key, key);
            // step 2. calloc memory
            plaintext = (uint8_t *)calloc(blockBytes,sizeof(uint8_t));
            if (!plaintext)
                return FEISTAL_BOX_MEMORY_NOT_ENOUGH;

            uint8_t buffer[blockBytes];
            uint32_t p = 0;
            
            uint8_t * dst = box_table;
            while(p<upper) {
                uint32_t t = m_htole32(p);
                *(uint32_t*)plaintext = t;
                // buffer = box->box[p* outputBytes ]
                sm4_encrypt(plaintext, buffer, &sm4_key);
                memcpy(dst, buffer, outputBytes);
                dst += outputBytes;
                ++p;
            }
            free(plaintext);   
            return dst-box_table; 
            break;
        }
        default:
        {
            return FEISTAL_BOX_NOT_IMPLEMENT;
            break;
        }
    }
    return ret;
}

int feistalRoundEnc(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output)
{
    int ret = 0;
    if ((ret = checkFeistalBox(box)))
        return ret;
    if (block_input==NULL || block_output==NULL)
        return ret = FEISTAL_ROUND_NULL_BLOCK_PTR;
    int _rounds = box->rounds;
    int i, j;
    int _bb = box->blockBytes;
    int _ib = box->inputBytes, _ob = box->outputBytes;
    const uint8_t* _table = box->table;
    uint8_t * p1 = (uint8_t *)malloc(sizeof(_bb));
    uint8_t * p2 = (uint8_t *)malloc(sizeof(_bb));
    if (!p1 || !p2)
        return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    memcpy(p1, block_input, _bb);
    for (i=0; i < _rounds; i++) 
    {
        unsigned long long int offset = 0;
        for (j=0; j<_ib; j++)
        {
            offset = (offset<<8) + p1[j];
            p2[_bb-_ib+j] = p1[j];
        }
        const uint8_t * rk = _table + (offset * _ob);
        for (; j<_bb; j++)
        {
            p2[j-_ib] = rk[j-_ib] ^ p1[j];
        }
        uint8_t *t = p1;
        p1 = p2;
        p2 = t;
   }
    memcpy(block_output, p1, _bb);
    return ret;
}


int feistalRoundDec(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output)
{
    int ret = 0;
    if ((ret = checkFeistalBox(box)))
        return ret;
    if (block_input==NULL || block_output==NULL)
        return ret = FEISTAL_ROUND_NULL_BLOCK_PTR;
    int _rounds = box->rounds;
    int i, j;
    int _bb = box->blockBytes;
    int _ib = box->inputBytes, _ob = box->outputBytes;
    const uint8_t* _table = box->table;
    uint8_t * p1 = (uint8_t *)malloc(sizeof(_bb));
    uint8_t * p2 = (uint8_t *)malloc(sizeof(_bb));
    if (!p1 || !p2)
        return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    memcpy(p1, block_input, _bb);
    for (i=0; i < _rounds; i++) 
    {
        uint8_t *t;
        //ror
        for (j=0; j<_ib; ++j)
        {
            p2[j]=p1[_bb-_ib+j];
        }
        for (j=_ib; j<_bb; ++j)
        {
            p2[j]=p1[j-_ib];
        }
        //swap
        t = p1;
        p1 = p2;
        p2 = t;
        
        unsigned long long int offset = 0;
        for (j=0; j<_ib; j++)
        {
            offset = (offset<<8) + p1[j];
            p2[_bb-_ib+j] = p1[j];
        }
        const uint8_t * rk = _table + (offset * _ob);
        for (; j<_bb; j++)
        {
            p2[j-_ib] = rk[j-_ib] ^ p1[j];
        }
        t = p1;
        p1 = p2;
        p2 = t;

        //ror
        for (j=0; j<_ib; ++j)
        {
            p2[j]=p1[_bb-_ib+j];
        }
        for (j=_ib; j<_bb; ++j)
        {
            p2[j]=p1[j-_ib];
        }
        //swap
        t = p1;
        p1 = p2;
        p2 = t;
   }
    memcpy(block_output, p1, _bb);
    return ret;
}