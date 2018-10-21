/**
 * @brief 
 * 
 * @file wbc2.h
 * @author liweijie
 * @date 2018-09-05
 */

#ifndef HEADER_WBC2_H
#define HEADER_WBC2_H

#include <AisinoSSL/sm4/sm4.h>
#include <AisinoSSL/aes/aes.h>
#include <stdint.h>

# ifdef  __cplusplus
extern "C" {
# endif

#define FEISTAL_ROUNDS 300
#define FEISTAL_MAX_ROUNDS 10000


#define FEISTAL_ALGOS_NUM 2
enum FeistalBoxAlgo {
    FeistalBox_AES_128_128 = 1,
    FeistalBox_SM4_128_128
};

enum E_FeistalBoxEncMode
{
    eFeistalBoxModeUnDefined = 0,
    eFeistalBoxModeDec = 1,
    eFeistalBoxModeEnc = 2
};

typedef struct FeistalBoxConfig {
    enum FeistalBoxAlgo algo;
    int rounds;
    int blockBytes ;
    int inputBytes ;
    int outputBytes ;
    int affine_on;
    uint8_t key[16];
} FeistalBoxConfig;

typedef struct FeistalBox {
    enum FeistalBoxAlgo algo;
    int rounds;
    int blockBytes ;
    int inputBytes ;
    int outputBytes ;
    int affine_on;
    enum E_FeistalBoxEncMode enc_mode;
    int tableSize;
    int pSize; 
    uint8_t encode[16][256];
    uint8_t decode[16][256];
    uint8_t *table;       // finally, box = 2^(8*inputBytes) * outputBytes
    uint8_t (*p)[16][256]; //permutation layer, size: rounds * 512B
} FeistalBox;

/**
 * USAGE:
 * 
 * Step 1.
 *      initFeistalBox 
 * Step 2.
 *      generateFeistalBox
 * Step 3.
 *      feistalRound
 * Step 4.
 *      releaseFeistalBox
 * 
 **/


int initFeistalBoxConfig(enum FeistalBoxAlgo algo, const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBoxConfig *cfg);
int initFeistalBoxConfigNoAffine(enum FeistalBoxAlgo algo, const uint8_t *key, int inputBytes, int outputBytes, int rounds, FeistalBoxConfig *cfg);

/**
 * @brief inputBytes + outputBytes should be 16
 * 
 * @param key 
 * @param inputBytes less than 4
 * @param outputBytes 
 * @param box 
 * @return int 
 */
int generateFeistalBox(const FeistalBoxConfig *cfg, enum E_FeistalBoxEncMode mode, FeistalBox *box);
int releaseFeistalBox(FeistalBox *box);

int feistalRoundEnc(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output);

int feistalRoundDec(const FeistalBox *box, const uint8_t *block_input, uint8_t * block_output);

// ERROR CODE DEFINE
#define FEISTAL_NULL_PTR -001

#define FEISTAL_BOX_NOT_IMPLEMENT -101
#define FEISTAL_BOX_INVALID_ALGO -102
#define FEISTAL_BOX_INVAILD_ARGUS -104
#define FEISTAL_BOX_INVALID_BOX -105
#define FEISTAL_BOX_MEMORY_NOT_ENOUGH -106

#define FEISTAL_ROUND_NULL_BLOCK_PTR -201
#define FEISTAL_ROUND_NUM_TOO_SMALL -202
#define FEISTAL_ROUND_NUM_TOO_BIG -203
#define FEISTAL_ROUND_ENC_MODE_INVALID -204

# ifdef  __cplusplus
}
# endif

#endif // HEADER_WBC2_H