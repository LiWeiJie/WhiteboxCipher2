/*
 * @Author: Weijie Li 
 * @Date: 2017-11-07 19:24:54 
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2017-11-28 11:23:34
 */


#ifndef  AISINOSSL_SM4_WHITEBOX_GENERATOR_H_
#define  AISINOSSL_SM4_WHITEBOX_GENERATOR_H_

 #include <stdint.h>

 #include <AisinoSSL/sm4_whitebox/sm4_whitebox.h>

#ifdef __cplusplus
extern "C" {
#endif

 #if SM4_WHITEBOX_F

#if SM4_WHITEBOX_DUMMYROUND_F
   /**
    * @brief generate Sm4Whitebox instance with dummy round
    * 
    * @param key encrypt key
    * @param sm4_wb_ctx a pointer to an instance of sm4_wb_ctx
    * @param enc encrypto mode. {SM4_ENCRYPT: encrypto mode; SM4_DECRYPT: decrypto mode}
    * @param dummyrounds add extra dummyrounds, 1 dummyround will be expanded to 4 rounds in the runtime
    * @return int 0 is successful, otherwise fault
    */
    int sm4_wb_gen_tables_with_dummyrounds(const uint8_t *key, Sm4Whitebox *sm4_wb_ctx, int enc, int dummyrounds);

#endif /* SM4_WHITEBOX_DUMMYROUND_F */

/**
 * @brief generate Sm4Whitebox instance  
 * 
 * @param key encrypt key
 * @param sm4_wb_ctx a pointer to an instance of sm4_wb_ctx
 * @param enc encrypto mode. {SM4_ENCRYPT: encrypto mode; SM4_DECRYPT: decrypto mode}
 * @return int 0 is successful, otherwise fault
 */
int sm4_wb_gen_tables(const uint8_t *key, Sm4Whitebox *sm4_wb_ctx, int enc);

 #endif /* SM4_WHITEBOX_F */

#ifdef __cplusplus
}
#endif
#endif /* AISINOSSL_SM4_WHITEBOX_GENERATOR_H_ */