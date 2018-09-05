#ifndef  AISINOSSL_SM4_WHITEBOX_CONFIG_H_
#define  AISINOSSL_SM4_WHITEBOX_CONFIG_H_

#ifndef ANDROID_MK_VER
#include <AisinoSSL/aisinossl_config.h>
#endif

 #ifdef SM4_WHITEBOX_ENABLE
    #define SM4_WHITEBOX_F     1

    #define SM4_WHITEBOX_DEBUG_INFO_F             0
    #define SM4_WHITEBOX_ROUND_MAX SM4_NUM_ROUNDS

    #define SM4_WHITEBOX_UNROLL_F              0

    #if DUMMY_ROUND_ENABLE
        #define SM4_WHITEBOX_DUMMYROUND_F 1
        #define SM4_WHITEBOX_DUMMY_ROUND_MAX 30        //max dummy round
        #define SM4_WHITEBOX_ROUND_MAX (SM4_NUM_ROUNDS+SM4_WHITEBOX_DUMMY_ROUND_MAX)  //max round number
    #else
        #define SM4_WHITEBOX_DUMMYROUND_F 0
        #define SM4_WHITEBOX_DUMMY_ROUND_MAX 0
    #endif //DUMMY_ROUND_ENABLE

    #define SM4_WHITEBOX_NUM_STATES (SM4_WHITEBOX_ROUND_MAX+4)

 #endif /* SM4_WHITEBOX_ENABLE */

#endif //AISINOSSL_SM4_WHITEBOX_CONFIG_H_
