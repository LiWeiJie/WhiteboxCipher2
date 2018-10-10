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

#include <AisinoSSL/math/affine_transform.h>
// #include <AisinoSSL/internal/aisinossl_random.h>

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
    int ret = 0;
    // step 1. check algo
    if (box->algo<1 || box->algo > FEISTAL_ALGOS_NUM)
        return ret = FEISTAL_BOX_INVALID_ALGO;
    // step 2. check block bytes
    if (box->blockBytes != 16) {
        return ret = FEISTAL_BOX_INVALID_BOX;
    }

    if (box->inputBytes > 4)
        return ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (box->outputBytes > box->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (box->inputBytes+box->outputBytes != box->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (box->rounds<1)
        return ret = FEISTAL_ROUND_NULL_ROUND_TOO_SMALL;
    if (box->rounds>FEISTA_MAX_ROUNDS)
        return ret = FEISTAL_ROUND_NULL_ROUND_TOO_BIG;

    return ret;
}

uint32_t swap32(uint32_t num) 
{
    return ((num>>24)&0xff) | // move byte 3 to byte 0
                    ((num<<8)&0xff0000) | // move byte 1 to byte 2
                    ((num>>8)&0xff00) | // move byte 2 to byte 1
                    ((num<<24)&0xff000000);
}

#define m_htole32(p) swap32(htons(p))

struct PermutationHelper
{
    uint8_t (*alpha)[16][256];
    uint8_t (*alpha_inv)[16][256];
    uint8_t (*beta)[16][256];
    uint8_t (*beta_inv)[16][256];
    uint8_t encode[16][256];
    uint8_t encode_inv[16][256];
    uint8_t decode[16][256];
    uint8_t decode_inv[16][256];
};


#define RANDOM_AFFINE_MAT(x, xi, d)   GenRandomAffineTransform(x, xi, d)

int initPermutationHelper(int rounds, struct PermutationHelper *ph)
{
    int ret = 0;
    ph->alpha = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    ph->alpha_inv = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    if (ph->alpha==NULL || ph->alpha_inv==NULL)
        return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    ph->beta = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    ph->beta_inv = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    if (ph->beta==NULL || ph->beta_inv==NULL)
        return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;

    MatGf2 tmg = NULL; //temp MatGf2
    MatGf2 tmg_inv = NULL;
    AffineTransform tat; //temp AffineTransform
    AffineTransform tat_inv;
    RANDOM_AFFINE_MAT(&tat, &tat_inv, 8);
    int i,j;
    for (i=0; i<16; i++)
    {
        for (j=0; j<256; j++) 
        {
            //TODO: add left mul and right mul for affinetransform
            // ph->encode[i][j] = 
        }
    }

    
    return ret;
}

int addPermutationLayer(int rounds, FeistalBox *box)
{
    int ret = 0;
    struct PermutationHelper ph;
    if ((ret = initPermutationHelper(rounds, &ph)))
        return ret;
    
    
    return ret;
}


//
int generateFeistalBox(const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBox *box)
{
    int ret = 0;
        
    box->inputBytes = inputBytes;
    box->rounds = rounds;
    box->outputBytes = outputBytes;

    if ((ret = checkFeistalBox(box)))
        return ret;

    // 1. generate T box
    uint8_t *plaintext;
    enum FeistalBoxAlgo algo = box->algo;

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
                return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;
            
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
                return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;

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
            break;
        }
        default:
        {
            return ret = FEISTAL_BOX_NOT_IMPLEMENT;
            break;
        }
    }

    // 2. add permutation layer
    ret = addPermutationLayer(rounds, box);

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
            p2[j] = p1[j];
        }
        const uint8_t * rk = _table + (offset * _ob);
        for (; j<_bb; j++)
        {
            p2[j] = rk[j-_ib] ^ p1[j];
        }
        t = p1;
        p1 = p2;
        p2 = t;

   }
    memcpy(block_output, p1, _bb);
    return ret;
}