/**
 * @brief 
 * 
 * @file wbc2.c
 * @author liweijie
 * @date 2018-09-05
 */

#include <assert.h>
// #include <machine/endian.h>

#include <wbc2/wbc2.h>
#include <AisinoSSL/sm4/sm4.h>

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

int checkFeistalBox(FeistalBox *box)
{
    // step 1. check algo
    if (box->algo<1 || box->algo > FEISTAL_ALGOS_NUM)
        return 0;
    // step 2. check block bytes
    if (box->blockBytes != 16) {
        return 0;
    }
    return 1;
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
int generateFeistalBox(const uint8_t *key, int inputBytes, int outputBytes, FeistalBox *box)
{
    assert(inputBytes <= 4);
    if (inputBytes > 4)
        return FEISTAL_BOX_NOT_IMPLEMENT;
    box->inputBytes = inputBytes;

    assert(outputBytes <= box->blockBytes);
    if (outputBytes > box->blockBytes)
        return  FEISTAL_BOX_INVAILD_ARGUS;

    assert(inputBytes+outputBytes == box->blockBytes);
    if (inputBytes+outputBytes != box->blockBytes)
        return  FEISTAL_BOX_INVAILD_ARGUS;
    
    box->outputBytes = outputBytes;
    uint8_t *plaintext;
    enum FeistalBoxAlgo algo = box->algo;
    if (!checkFeistalBox(box))
        return FEISTAL_BOX_INVALID_BOX;

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
    return 0;
}

int feistalRoundEnc(FeistalBox *box, const uint8_t *plaintext, int rounds, uint8_t * ciphertext)
{
    int i, j;
    int _bb = box->blockBytes;
    int _ib = box->inputBytes, _ob = box->outputBytes;
    uint8_t* _table = box->table;
    uint8_t * p1 = (uint8_t *)malloc(sizeof(_bb));
    uint8_t * p2 = (uint8_t *)malloc(sizeof(_bb));
    if (!p1 || !p2)
        return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    memcpy(p1, plaintext, _bb);
    for (i=0; i < rounds; i++) 
    {
        unsigned long long int offset = 0;
        for (j=0; j<_ib; j++)
        {
            offset = (offset<<8) + p1[j];
            p2[_bb-_ib+j] = p1[j];
        }
        uint8_t * rk = _table + (offset * _ob);
        for (; j<_bb; j++)
        {
            p2[j] = rk[j-_ib] ^ p1[j];
        }
        uint8_t *t = p1;
        p1 = p2;
        p2 = t;
   }
    memcpy(ciphertext, p1, _bb);
    return 0;
}
