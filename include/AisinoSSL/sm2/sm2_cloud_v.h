/*
 * sm2_cloud_v.h
 *
 *  Created on: 2017.10.1
 *      Author: lzj
 *
 * if you want to know how to using the sm2 cloud signature ,see {@link sm2_cloud_v_self_test }
 * which a test demo to tell you.
 */


#ifndef SM2_CLOUD_V_H_
#define SM2_CLOUD_V_H_


#include <AisinoSSL/mbedtls/ecp.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * hash function such as sm3
 * @return
 */
typedef void (*hash_function32)(const unsigned char *input, size_t ilen,
		unsigned char output[32]);


/**
 * random function such as
 * @return
 */
typedef int (*rand_function)(mbedtls_mpi *k, mbedtls_mpi *range);


/**
 * KP = {g, N, N^2, Q}
 * server generate param
 */
typedef struct {
	mbedtls_mpi g;
	mbedtls_mpi N;
	mbedtls_mpi n;  //N^2
	mbedtls_ecp_point Q;
} sm2_cloud_v_KP_context;


/**
 * server context ,which contain KP
 */
typedef struct {
	mbedtls_ecp_group grp;
	sm2_cloud_v_KP_context kp;
	mbedtls_mpi r;
	mbedtls_mpi u;
	mbedtls_mpi ks;
	mbedtls_mpi u2;
} sm2_cloud_v_server_context;

/**
 * MobileSM2UserKeyGen  algorithm param ,that is used in transfer key information
 * such as {ptk1,W,ptk2}
 */
typedef struct {
	mbedtls_ecp_point W;
	mbedtls_mpi ptk1;
	mbedtls_mpi ptk2;
} sm2_cloud_v_key_info;


/**
 * client context
 */
typedef struct {
	mbedtls_ecp_group grp;
	mbedtls_mpi n;  //N^2
	mbedtls_ecp_point P_a;
	mbedtls_mpi hd1;
	mbedtls_mpi hd2;
	mbedtls_mpi k1;
	mbedtls_mpi u1;
} sm2_cloud_v_client_context;


/**
 * signature param  for transfer signature information
 * such as {hs1,hs2,Q} , {hs3,hs4,Q_A} or {PA,r,hs}
 */
typedef struct {
	mbedtls_ecp_point Q;      // Q, Q_A or PA
	mbedtls_mpi h_1;        //hs1, hs3 or r
	mbedtls_mpi h_2;        //hs2, hs4 or hs
} sm2_cloud_v_sign_param;




/**
 * random function generate a random number from 0 to range -1
 *
 * @param  k     [out]  the result random number
 *
 * @param  range [in]		the range
 *
 * @return       [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_rand_range(mbedtls_mpi *k, mbedtls_mpi *range);


/**
 * client context init
 *
 * @param  ctx  [in]	client context
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_client_ctx_init(sm2_cloud_v_client_context *ctx);

/**
 * client context free
 *
 * @param ctx [in]		client context
 */
void sm2_cloud_v_client_ctx_free(sm2_cloud_v_client_context *ctx);


/**
 * server context init
 *
 * @param  ctx [in]		server context
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_server_ctx_init(sm2_cloud_v_server_context *ctx);


/**
 * server context free
 *
 * @param ctx [in]		server context
 */
void sm2_cloud_v_server_ctx_free(sm2_cloud_v_server_context *ctx);


/**
 * key information context init
 *
 * @param ctx [in]		key information context
 */
void sm2_cloud_v_key_info_init(sm2_cloud_v_key_info *ctx);


/**
 * key information context free
 *
 * @param ctx [in]		key information context
 */
void sm2_cloud_v_key_info_free(sm2_cloud_v_key_info *ctx);


/**
 * signature param context init
 *
 * @param ctx [in]		signature param context
 */
void sm2_cloud_v_sign_param_init(sm2_cloud_v_sign_param *ctx);

/**
 * signature param context free
 *
 * @param ctx [in]		signature param context
 */
void sm2_cloud_v_sign_param_free(sm2_cloud_v_sign_param *ctx);


/**
 * server function: the first setp, server  generate the signature param and send the KP to client
 *
 * @param  ctx    [in] 		server context
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return        [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_server_gen_key_param(sm2_cloud_v_server_context *ctx,
		rand_function rand_f);


/**
 * server function:	generate the key information and send it to client to help her
 * to generate the complete key pair
 *
 * @param  server [in]		server context
 *
 * @param  out    [out]		key information context
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return       [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_server_key_gen(sm2_cloud_v_server_context *server,
		sm2_cloud_v_key_info *out, rand_function rand_f);


/**
 * client function: when get the param from server then client can generate her key pair.
 *
 * @param  key_param [in]		key information context that come from server {@link sm2_cloud_v_server_key_gen}
 *
 * @param  kp        [in]		KP param that also come from server {@link sm2_cloud_v_server_gen_key_param}
 *
 * @param  out       [out]	client context that contain the key pair information
 *
 * @param  rand_f    [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return           [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_client_key_gen(sm2_cloud_v_key_info *key_param,
		sm2_cloud_v_KP_context *kp, sm2_cloud_v_client_context *out,
		rand_function rand_f);

/**
 * signature step1;
 *
 * client function: when client want to signature,she has to prepare the information
 * and send the request to server {@param sp}
 *
 * @param  ctx    [in]		client context that contain key information,such as generate in {@sm2_cloud_v_client_key_gen}
 *
 * @param  sp     [out]		signature information that send to the server
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return        [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_client_sign_prepare(sm2_cloud_v_client_context *ctx,
		sm2_cloud_v_sign_param *sp, rand_function rand_f);


/**
 * signature step2;
 *
 * server function: when server get the signature request from client ,he use the sp to
 * generate signature information and set other sp to  client.
 *
 * @param  ctx    [in]		server context
 *
 * @param  sp     [in and out]	signature param, [in]the client has sent to server {@sm2_cloud_v_client_sign_prepare},
 *                							after calculate will assign the new value to the sp[out].
 *
 * @param  rand_f [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return        [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_server_sign_prepare(sm2_cloud_v_server_context *ctx,
		sm2_cloud_v_sign_param *sp, rand_function rand_f);


/**
 * signature step3;
 *
 * client function: has read and start to signature the messgae
 *
 * @param  ctx     [in]		client context
 *
 * @param  sp      [in]		signature param that come from server {@sm2_cloud_v_server_sign_prepare}
 *
 * @param  out     [out]  signature information need to send to server .
 *
 * @param  id      [in]		user id
 *
 * @param  idlen   [in]		id string length
 *
 * @param  message [in]		message
 *
 * @param  msglen  [in]		message string length
 *
 * @param  rand_f  [in]		random function  such as {@link sm2_cloud_v_rand_range}
 *
 * @return         [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_client_sign(sm2_cloud_v_client_context *ctx,
		sm2_cloud_v_sign_param *sp, sm2_cloud_v_sign_param *out,
		const char *id, size_t idlen, const char *message, size_t msglen, rand_function rand_f);


/**
 * signature step4;
 *
 * server function: server generate a complete signature for message. and the signature to client.
 *
 * @param  ctx         [in]		server context
 *
 * @param  sps         [in]		 signature information that come from client  {@sm2_cloud_v_client_sign}
 *
 * @param  id      		 [in]		user id
 *
 * @param  idlen   		 [in]		id string length
 *
 * @param  message 		 [in]		message
 *
 * @param  msglen 	   [in]		message string length
 *
 * @param  out         [out]	signature byte
 *
 * @param  max_out_len [in]		out array length
 *
 * @param  olen        [out]	the signature byte length
 *
 * @return             [flag]	if successfully 0, otherwise failed.
 */
int sm2_cloud_v_server_sign(sm2_cloud_v_server_context *ctx,
		sm2_cloud_v_sign_param *sps, const char *id, size_t idlen,
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
int sm2_cloud_v_sign_verify(mbedtls_ecp_group *grp, mbedtls_ecp_point *P_a,
		const char *id, size_t idlen, const char *message, size_t msglen,
		const unsigned char *dgst, size_t dgstlen);


/**
 * sm2 cloud test demo
 *
 * @param  verbose [in]  no meaning
 *
 * @return         [flag]	if successfully 0, otherwise failed.
 *
 */
int sm2_cloud_v_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* SM2_CLOUD_H_ */
