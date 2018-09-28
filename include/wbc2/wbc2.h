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

#define FEISTAL_ALGOS_NUM 2
enum FeistalBoxAlgo {
    FeistalBox_AES_128_128 = 1,
    FeistalBox_SM4_128_128
};

typedef struct FeistalBox {
    enum FeistalBoxAlgo algo;
    int blockBytes ;
    int inputBytes ;
    int outputBytes ;
    uint8_t *table;       // finally, box = 2^(8*inputBytes) * outputBytes
    int tableSize;
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


int initFeistalBox(enum FeistalBoxAlgo algo, FeistalBox *box);

int generateFeistalBox(const uint8_t *key, int inputBytes, int outputBytes, FeistalBox *box);
int releaseFeistalBox(FeistalBox *box);

int feistalRoundEnc(FeistalBox *box, const uint8_t *plaintext, int rounds, uint8_t * ciphertext);

// ERROR CODE DEFINE
#define FEISTAL_BOX_NOT_IMPLEMENT -1
#define FEISTAL_BOX_INVALID_ALGO -2
#define FEISTAL_BOX_INVAILD_ARGUS -4
#define FEISTAL_BOX_INVALID_BOX -5
#define FEISTAL_BOX_MEMORY_NOT_ENOUGH -6


# ifdef  __cplusplus
}
# endif

#endif // HEADER_WBC2_H