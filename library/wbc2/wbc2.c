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

#include "matrixlib/affine_transform.h"
// #include <AisinoSSL/internal/aisinossl_random.h>

#ifdef WIN32
#include <winsock.h>
#endif

// #define DEBUG 1

int checkFeistalBoxConfig(const FeistalBoxConfig *cfg);

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



int _initFeistalBox(enum FeistalBoxAlgo algo, const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBoxConfig *cfg, int affine_on) 
{
    switch (algo) {
        case FeistalBox_AES_128_128:
            cfg->affine_on = affine_on;
            cfg->algo = algo;
            cfg->blockBytes = 16;
            cfg->inputBytes = inputBytes;
            cfg->outputBytes = outputBytes;
            cfg->rounds = rounds;
            // cfg->key = (uint8_t *)malloc(16);
            // if (cfg->key==NULL)
                // return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
            memcpy(cfg->key, key, 16);
            break;
        case FeistalBox_SM4_128_128:
            cfg->affine_on = affine_on;
            cfg->algo = algo;
            cfg->blockBytes = 16;
            cfg->inputBytes = inputBytes;
            cfg->outputBytes = outputBytes;
            cfg->rounds = rounds;
            // cfg->key = (uint8_t *)malloc(16);
            // if (cfg->key==NULL)
                // return FEISTAL_BOX_MEMORY_NOT_ENOUGH;
            memcpy(cfg->key, key, 16);
            break;
        default:
            return FEISTAL_BOX_INVALID_ALGO;
            break;
    }
    return 0;
}

int initFeistalBoxConfig(enum FeistalBoxAlgo algo, const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBoxConfig *cfg)
{
    int ret = 0;
    if ((ret = _initFeistalBox(algo, key, inputBytes, outputBytes, rounds, cfg, 1)))
        return ret;
    return ret = checkFeistalBoxConfig(cfg);
}

int initFeistalBoxConfigNoAffine(enum FeistalBoxAlgo algo, const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBoxConfig *cfg)
{
    return _initFeistalBox(algo, key, inputBytes, outputBytes, rounds, cfg, 0);
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
int checkFeistalBoxConfig(const FeistalBoxConfig *cfg)
{
    int ret = 0;
    if (cfg==NULL)
        return ret = FEISTAL_NULL_PTR;
    // step 1. check algo
    if (cfg->algo<1 || cfg->algo > FEISTAL_ALGOS_NUM)
        return ret = FEISTAL_BOX_INVALID_ALGO;
    // step 2. check block bytes
    if (cfg->blockBytes != 16) {
        return ret = FEISTAL_BOX_INVALID_BOX;
    }

    if (cfg->inputBytes > 4)
        return ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (cfg->outputBytes > cfg->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (cfg->inputBytes+cfg->outputBytes != cfg->blockBytes)
        return  ret = FEISTAL_BOX_INVAILD_ARGUS;

    if (cfg->rounds<1)
        return ret = FEISTAL_ROUND_NUM_TOO_SMALL;
    if (cfg->rounds>FEISTAL_MAX_ROUNDS)
        return ret = FEISTAL_ROUND_NUM_TOO_BIG;

    return ret;
}

int checkFeistalBox(const FeistalBox *box)
{
    int ret = 0;
    if (box==NULL)
        return ret = FEISTAL_NULL_PTR;
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
        return ret = FEISTAL_ROUND_NUM_TOO_SMALL;
    if (box->rounds>FEISTAL_MAX_ROUNDS)
        return ret = FEISTAL_ROUND_NUM_TOO_BIG;

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
    uint8_t (*alpha_inv2)[16][256];
    // uint8_t (*beta)[16][256];
    // uint8_t (*beta_inv)[16][256];
    // uint8_t (*beta_inv2)[16][256];
    uint8_t encode[16][256];
    uint8_t encode_inv[16][256];
    uint8_t encode_inv2[16][256];
};


#define RANDOM_AFFINE_MAT(x, xi, d)   GenRandomAffineTransform(x, xi, d)

#include <stdio.h>
int initPermutationHelper(int rounds, struct PermutationHelper *ph)
{
    int ret = 0;
    ph->alpha = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    ph->alpha_inv = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    ph->alpha_inv2 = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    if (ph->alpha==NULL || ph->alpha_inv==NULL || ph->alpha_inv2==NULL )
        return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    // ph->beta = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    // ph->beta_inv = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    // ph->beta_inv2 = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    // if (ph->beta==NULL || ph->beta_inv==NULL || ph->beta_inv2==NULL )
    //     return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;

    MatGf2 tmg = NULL; //temp MatGf2
    MatGf2 tmg_inv = NULL;
    AffineTransform tata; //temp AffineTransform
    AffineTransform tata_inv;
    AffineTransform tatb; //temp AffineTransform
    AffineTransform tatb_inv;
    int i,j;
    for (i=0; i<16; i++)
    {
        RANDOM_AFFINE_MAT(&tata, &tata_inv, 8);
        RANDOM_AFFINE_MAT(&tatb, &tatb_inv, 8);

        for (j=0; j<256; j++) 
        {
            uint8_t t = AffineMulU8(tata, j);
            ph->encode[i][j] = U8MulAffine(t, tatb);
            ph->encode_inv[i][ ph->encode[i][j] ] = j;
            ph->encode_inv2[i][ U8MulMat( MatMulU8(tata.linear_map, j), tatb.linear_map) ] = j;
            // assert(AffineMulU8(tata_inv, ph->encode[i][j])==j);
            // ph->encode_inv[i][ ph->encode[i][j] ] = j;
        }
    }    

    int r;
    for (r=0; r<rounds; r++)
    {
        for (i=0; i<16; i++)
        {
            RANDOM_AFFINE_MAT(&tata, &tata_inv, 8);
            RANDOM_AFFINE_MAT(&tatb, &tatb_inv, 8);
            for (j=0; j<256; j++) 
            {
                uint8_t t = AffineMulU8(tata, j);
                ph->alpha[r][i][j] = U8MulAffine(t, tatb);
                ph->alpha_inv[r][i][ ph->alpha[r][i][j] ] = j;
                ph->alpha_inv2[r][i][ U8MulMat( MatMulU8(tata.linear_map, j), tatb.linear_map) ] = j;
            }
        }
    }
    
    return ret;
}

int releasePermutationHelper(int rounds, struct PermutationHelper *ph)
{
    free(ph->alpha);
    free(ph->alpha_inv);
    free(ph->alpha_inv2);
    ph->alpha = ph->alpha_inv = ph->alpha_inv2 = NULL;
    return 0;
}

int addEncPermutationLayer(const struct PermutationHelper *ph, FeistalBox *box)
{
    int ret = 0;
    int rounds = box->rounds;


    box->p = (uint8_t (*)[16][256]) malloc(rounds*4096*sizeof(uint8_t));
    if (box->p==NULL)
        return ret = FEISTAL_BOX_MEMORY_NOT_ENOUGH;
    
    const int _ob = box->outputBytes;
    const int _ib = box->inputBytes;
    const int _bb = box->blockBytes;
    uint64_t upper = ((long long)1<<(8*_ib));
    int r;
    uint8_t * otable = box->table;
    box->table = (uint8_t*) malloc(rounds * _ob * upper);
    uint8_t digital[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint64_t pos = 0;
    int i, j;

    uint8_t (*table_ptr);
    table_ptr = box->table;
    for (r=0; r<rounds; r++)
    {
        for (pos=0; pos<upper; pos++)
        {
            digital[_ib-1]++;
            for (j=_ib-2; j>=0; j--)
            {
                if (digital[j+1]==0)
                {
                    digital[j]++;
                } else {
                    break;
                }
            }
            
            const uint8_t (*prev_ptr)[16][256];
            const uint8_t (*prev_inv_ptr)[16][256];
            const uint8_t (*prev_inv2_ptr)[16][256];
            const uint8_t (*current_ptr)[16][256];

            if (r==0)
            {
                prev_ptr = &(ph->encode);
                prev_inv_ptr = &(ph->encode_inv);
                prev_inv2_ptr = &(ph->encode_inv2);
            } else {
                prev_ptr = &(ph->alpha[r-1]);
                prev_inv_ptr = &(ph->alpha_inv[r-1]);
                prev_inv2_ptr = &(ph->alpha_inv2[r-1]);
            }
            current_ptr = &(ph->alpha[r]);
            unsigned long long int offset1 = 0;
            unsigned long long int offset2 = 0;

            for (j=0; j<_ib; j++) 
            {
                offset1 = (offset1<<8) + (*prev_inv_ptr)[j][digital[j]];
                offset2 = (offset2<<8) + digital[j];
            }
            uint8_t *ptr = table_ptr + offset2*_ob;
            uint8_t *optr = otable + offset1*_ob;
            for (j=_ib; j<_bb; j++)
            {
                ptr[j-_ib] =   (*prev_ptr)[j][ optr[j-_ib] ];
            }

            for (i=0; i<16; ++i)
            {
                for (j=0; j<256; ++j)
                {
                    if (i<_ob) {
                        box->p[r][i][j] = (*current_ptr)[i][(*prev_inv2_ptr)[ (i+_ib)%_bb ][j]];
                    }
                    else {
                        box->p[r][i][j] = (*current_ptr)[i][(*prev_inv_ptr)[ (i+_ib)%_bb ][j]];
                    }
                }
            }            
        }
        table_ptr += _ob * upper;
    }

    memcpy(box->encode, ph->encode, 16*256);
    memcpy(box->decode, ph->alpha_inv[rounds-1], 16*256);
        
    free(otable);
    otable = NULL;

    return ret;
}


int addDecPermutationLayer(const struct PermutationHelper *ph, FeistalBox *box)
{
    return 0;
}

//
int generateFeistalBox(const FeistalBoxConfig *cfg, enum E_FeistalBoxEncMode mode, FeistalBox *box)
{
    int ret = 0;
    if (cfg==NULL || box==NULL)
        return ret = FEISTAL_NULL_PTR;
    if ((ret=checkFeistalBoxConfig(cfg)))
        return ret;
        
    box->inputBytes = cfg->inputBytes;
    box->rounds = cfg->rounds;
    box->outputBytes = cfg->outputBytes;
    box->blockBytes = cfg->blockBytes;
    box->affine_on = cfg->affine_on;
    box->algo = cfg->algo;
    box->enc_mode = mode;

    const uint8_t *key = cfg->key;
    int inputBytes = cfg->inputBytes;
    int outputBytes = cfg->outputBytes;
    int rounds = cfg->rounds;

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

    if (box->affine_on) {
        // 2. add permutation layer
        struct PermutationHelper ph;
        if ((ret = initPermutationHelper(rounds, &ph)))
            return ret;
        
        if (mode==eFeistalBoxEnc)
            ret = addEncPermutationLayer(&ph, box);
        else if (mode==eFeistalBoxDec)
            ret = addDecPermutationLayer(&ph, box);
        else 
            return ret = FEISTAL_ROUND_ENC_MODE_INVALID;

        if ((ret = releasePermutationHelper(rounds, &ph)))
            return ret;
        
    }
   
    return ret;
}

int feistalRoundEnc(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output)
{
    int ret = 0;
    if (box->enc_mode!=eFeistalBoxEnc)
        return ret = FEISTAL_ROUND_ENC_MODE_INVALID;

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

    const uint64_t upper = ((long long)1<<(8*_ib));
    if (box->affine_on) {
        for (i=0; i<_bb; i++)
        {
            p1[i] = box->encode[i][block_input[i]];
        }
    }  else {
        memcpy(p1, block_input, _bb);
    }

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

        if (box->affine_on)
        {
            for (j=0; j<_bb; j++)
            {
                p1[j] = box->p[i][j][p2[j]];
            }
            _table +=  _ob * upper;
        } else {
            uint8_t *t = p1;
            p1 = p2;
            p2 = t;
        }

        #ifdef DEBUG
            printf("Round %d:\n", i+1);
            dump(p1, 16);
        #endif
    }
    if (box->affine_on)
    {
        for (i=0; i<_bb; i++)
        {
            block_output[i] = box->decode[i][p1[i]];
        }
    } else {
        memcpy(block_output, p1, _bb);
    }
    return ret;
}

int feistalRoundDec(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output)
{
    int ret = 0;
    if (box->enc_mode!=eFeistalBoxDec)
        return ret = FEISTAL_ROUND_ENC_MODE_INVALID;
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

    const uint64_t upper = ((long long)1<<(8*_ib));
    if (box->affine_on)
    {
        for (i=0; i<_bb; i++)
        {
            p1[i] = box->encode[i][block_input[i]];
        }
    }  else {
        memcpy(p1, block_input, _bb);
    }

    for (i=0; i < _rounds; i++) 
    {
        unsigned long long int offset = 0;
        for (j=0; j<_ib; j++)
        {
            offset = (offset<<8) + p1[(_bb-_ib+j)%_bb];
            p2[j] = p1[ (_bb-_ib+j)%_bb ];
        }
        const uint8_t * rk = _table + (offset * _ob);
        for (; j<_bb; j++)
        {
            p2[j] = rk[j-_ib] ^ p1[(_bb-_ib+j)%_bb];
        }
        if (box->affine_on)
        {
            for (j=0; j<_bb; j++)
            {
                p1[j] = box->p[i][j][p2[j]];
            }
            _table +=  _ob * upper;
        } else {
            uint8_t *t = p1;
            p1 = p2;
            p2 = t;
        }
   }
    if (box->affine_on)
    {
        for (i=0; i<_bb; i++)
        {
            block_output[i] = box->decode[i][p1[i]];
        }
    } else {
        memcpy(block_output, p1, _bb);
    }    
    return ret;
}
