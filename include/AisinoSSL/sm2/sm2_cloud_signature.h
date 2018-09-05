/*
 * sm2_cloud_signature.h
 *
 *  Created on: 2017骞�11鏈�28鏃�
 *      Author: lzj
 */

#ifndef CRYPTO_LIBRARY_AISINOSSL_SM2_SM2_CLOUD_SIGNATURE_H_
#define CRYPTO_LIBRARY_AISINOSSL_SM2_SM2_CLOUD_SIGNATURE_H_

#include <AisinoSSL/mbedtls/bignum.h>
#include <AisinoSSL/mbedtls/ecp.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * hash function such as sm3
 * @return
 */
typedef void (*hash_fun32)(const unsigned char *input, size_t ilen,
		unsigned char output[32]);

/**
 * random function such as sm2_cloud_sign_rand_range
 * @return
 */
typedef int (*rand_fun)(mbedtls_mpi *k, mbedtls_mpi *range);

/**
 * KP = {g, N, N^2}
 * server generate param
 */
typedef struct {
	mbedtls_mpi g;
	mbedtls_mpi N;
	mbedtls_mpi n;  //N^2
} sm2_cloud_sign_kp_context;

/**
 * server context ,which contain KP
 */
typedef struct {
	mbedtls_ecp_group grp;
	sm2_cloud_sign_kp_context kp;
	mbedtls_mpi r;
	mbedtls_mpi u;
	mbedtls_mpi k2;
} sm2_cloud_sign_server_context;

/**
 * MobileSM2UserKeyGen  algorithm param ,that is used in transfer key information
 * such as {ptk1,W}
 */
typedef struct {
	mbedtls_ecp_point W;
	mbedtls_mpi ptk1;
} sm2_cloud_sign_key_info;

/**
 * client context
 */
typedef struct {
	mbedtls_ecp_group grp;
	mbedtls_ecp_point P_a;
	mbedtls_mpi hd_A;
//mbedtls_mpi n;  //N^2
} sm2_cloud_sign_client_context;

/**
 * signature param  for transfer signature information
 *
 */
typedef struct {
	mbedtls_mpi r;
	mbedtls_mpi hs1;
	mbedtls_mpi hs2;
	mbedtls_ecp_point P_a;
} sm2_cloud_sign_param;

/**
 *Q of the param which server sent to client
 */
typedef struct {
	mbedtls_ecp_point Q;
	mbedtls_mpi n;  //N^2
} sm2_cloud_sign_Q;


void sm2_cloud_sign_kp_init(sm2_cloud_sign_kp_context *kp);
void sm2_cloud_sign_kp_free(sm2_cloud_sign_kp_context *kp);

void sm2_cloud_sign_key_info_init(sm2_cloud_sign_key_info * info);
void sm2_cloud_sign_key_info_free(sm2_cloud_sign_key_info * info);

void sm2_cloud_sign_param_init(sm2_cloud_sign_param *param);
void sm2_cloud_sign_param_free(sm2_cloud_sign_param *param);

void sm2_cloud_sign_Q_init(sm2_cloud_sign_Q *Q);
void sm2_cloud_sign_Q_free(sm2_cloud_sign_Q *Q);


/**
 * random function generate a random number from 0 to range -1
 *
 * @param  k     [out]  the result random number
 *
 * @param  range [in]		the range
 *
 * @return       [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_rand_range(mbedtls_mpi *k, mbedtls_mpi *range);

/**
 * server context init
 *
 * @param  ctx [in]		server context
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_server_ctx_init(sm2_cloud_sign_server_context *ctx);

/**
 * server context free
 *
 * @param ctx [in]		server context
 */
void sm2_cloud_sign_server_ctx_free(sm2_cloud_sign_server_context *ctx);

/**
 * server function: the first setp, server  generate the signature param and send the KP to client
 *
 * @param  ctx    [in] 		server context
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_sign_rand_range}
 *
 * @return        [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_server_gen_key_param(sm2_cloud_sign_server_context *ctx,
		rand_fun rand_f);

/**
 * server function : MobileSM2UserKeyGen  algorithm ;
 *
 * @param  server [in]		server context
 *
 * @param  key    [out]		key information context
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_sign_rand_range}
 *
 * @return        [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_server_mobile_SM2UKG(sm2_cloud_sign_server_context *server,
		sm2_cloud_sign_key_info *key, rand_fun rand_f);

/**
 * client context init
 *
 * @param  ctx  [in]	client context
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_client_ctx_init(sm2_cloud_sign_client_context *ctx);

/**
 * client context free
 *
 * @param ctx [in]		client context
 */
void sm2_cloud_sign_client_ctx_free(sm2_cloud_sign_client_context *ctx);

/**
 * MobileSM2UserKeyGen  algorithm ;
 *
 * client function: when get the param from server then client can generate her key pair.
 *
 * @param  key       [in]		key information context that come from server {@link sm2_cloud_sign_server_gen_key_param}
 *
 * @param  kp        [in]		KP param that also come from server {@link sm2_cloud_sign_server_mobile_SM2UKG}
 *
 * @param  client    [out]		client context that contain the key pair information
 *
 * @param  rand_f    [in]		random function  such as {@link sm2_cloud_sign_rand_range}
 *
 * @return           [flag]		if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_client_mobile_SM2UKG(sm2_cloud_sign_key_info *key,
		sm2_cloud_sign_kp_context *kp, sm2_cloud_sign_client_context *client,
		rand_fun rand_f);

/**
 * signature step2;
 *
 * server function : response client signature request send the Q to client;
 *
 * @param  ctx       [in]		server context
 *
 * @param  Q      	 [out]		signature param Q.
 *
 * @param  rand_f    [in]		random function  such as {@link sm2_cloud_sign_rand_range}
 *
 * @return           [flag]		if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_server_sendQ(sm2_cloud_sign_server_context *ctx,
		sm2_cloud_sign_Q *Q, rand_fun rand_f);

/**
 * signature step3;
 *
 * client function: has read and start to signature the messgae
 *
 * @param  ctx     [in]		client context
 *
 * @param  Q       [in]		signature param that come from server {@sm2_cloud_sign_server_sendQ}
 *
 * @param  param   [out]    signature information need to send to server .
 *
 * @param  id      [in]		user id
 *
 * @param  idlen   [in]		id string length
 *
 * @param  message [in]		message
 *
 * @param  msglen  [in]		message string length
 *
 * @param  rand_f  [in]		random function  such as {@link sm2_cloud_sign_rand_range}
 *
 * @return         [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_client_sign(sm2_cloud_sign_client_context *ctx,
		sm2_cloud_sign_Q *Q, sm2_cloud_sign_param * param, const char *id,
		size_t idlen, const char *message, size_t msglen, rand_fun rand_f);

/**
 * signature step4;
 *
 * server function: server generate a complete signature for message. and the signature to client.
 *
 * @param  ctx        	 [in]		server context
 *
 * @param  param         [in]		 signature information that come from client  {@sm2_cloud_sign_client_sign}
 *
 * @param  id      		 [in]		user id
 *
 * @param  idlen   		 [in]		id string length
 *
 * @param  message 		 [in]		message
 *
 * @param  msglen 	  	 [in]		message string length
 *
 * @param  out       	 [out]		signature byte
 *
 * @param  max_out_len 	 [in]		out array length
 *
 * @param  olen      	 [out]		the signature byte length
 *
 * @return             	 [flag]		if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_server_sign(sm2_cloud_sign_server_context *ctx,
		sm2_cloud_sign_param *param, const char *id, size_t idlen,
		const char *message, size_t msglen, unsigned char *out,
		size_t max_out_len, size_t *olen);

/**
 * to verify the signature
 *
 * @param  grp     [in]		group
 *
 * @param  P_a     [in]		public key
 *
 * @param  id      [in]		user id
 *
 * @param  idlen   [in]		id string length
 *
 * @param  message [in]		message
 *
 * @param  msglen  [in]		message string length
 *
 * @param  dgst    [in]		signature bytes
 *
 * @param  dgstlen [in]		signature bytes length
 *
 * @return         [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_sign_sign_verify(mbedtls_ecp_group *grp, mbedtls_ecp_point *P_a,
		const char *id, size_t idlen, const char *message, size_t msglen,
		const unsigned char *dgst, size_t dgstlen);




int sm2_cloud_sign_client_mobile_SM2UKH(sm2_cloud_sign_client_context *ctx,
		const sm2_cloud_sign_kp_context *kp, const mbedtls_mpi *d,rand_fun rand_f);




int sm2_cloud_sign_client_mobile_SM2UKH_binary(sm2_cloud_sign_client_context *ctx,
		const sm2_cloud_sign_kp_context *kp, const unsigned char* d, int d_len,rand_fun rand_f);


int sm2_cloud_sign_client_mobile_SM2UKH_stringDEX(
		sm2_cloud_sign_client_context *ctx, const sm2_cloud_sign_kp_context *kp,
		const char* d,rand_fun rand_f);


int sm2_cloud_sign_client_set_public_key(sm2_cloud_sign_client_context *ctx,
		const mbedtls_ecp_point *pk);
int sm2_cloud_sign_client_set_public_key_binary(sm2_cloud_sign_client_context *ctx,
		const unsigned char* pk, int pk_len);
int sm2_cloud_sign_client_set_public_key_stringDEX(
		sm2_cloud_sign_client_context *ctx, const char* x, const char* y);

/**
 * sm2 cloud test demo
 *
 * @param  verbose [in]  no meaning
 *
 * @return         [flag]	if successfully 0, otherwise failed.
 *
 */
int sm2_cloud_sign_self_test(int verbose);
#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_LIBRARY_AISINOSSL_SM2_SM2_CLOUD_SIGNATURE_H_ */
