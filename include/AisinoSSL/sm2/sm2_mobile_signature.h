#ifndef CRYPTO_LIBRARY_AISINOSSL_SM2_SM2_MOBILE_SIGNATURE_H_
#define CRYPTO_LIBRARY_AISINOSSL_SM2_SM2_MOBILE_SIGNATURE_H_

#include <AisinoSSL/mbedtls/bignum.h>
#include <AisinoSSL/mbedtls/ecp.h>
#ifdef __cplusplus
extern "C" {
#endif

//密钥生成协议结构体说明
typedef struct {
	mbedtls_ecp_group grp;  //椭圆曲线参数
	mbedtls_mpi hd;         //密钥分片参数，服务器端为hds，用户端为hda   
	//mbedtls_ecp_point w;    //密钥分片传递参数，服务器端为ws,用户端为wa
	mbedtls_ecp_point P_a;  //公钥
} sm2_mobile_key_context;

//签名协议结构体说明
//用户端
typedef struct {
	sm2_mobile_key_context key;        //密钥生成协议结构
	mbedtls_ecp_point P1;				//P1
	mbedtls_ecp_point P2;				//P2
	mbedtls_mpi u, a1, a2;				//随机数u,a1,a2
	mbedtls_mpi r;						//签名前半部分r
} sm2_mobile_sign_client_context;

//服务器端
typedef struct {
	sm2_mobile_key_context key;		//密钥生成协议结构
	mbedtls_ecp_point P1;				//用户端传输的P1
	mbedtls_ecp_point P2;				//用户端传输的P2
	mbedtls_ecp_point Q1;				//Q1
	mbedtls_ecp_point Q2;				//Q2
	mbedtls_mpi s1, s2;					//随机数s1,s2
} sm2_mobile_sign_server_context;

/**
 * 密钥生成协议结构体初始化
 *
 * @param  ctx  [in]	密钥生成协议结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_key_init(sm2_mobile_key_context *ctx);

/**
 * 密钥生成协议结构体资源释放
 *
 * @param  ctx  [in]	密钥生成协议结构体
 *
 * @return     
 */
void sm2_mobile_key_free(sm2_mobile_key_context *ctx);

/**
 * 计算W的值，服务器端计算ws,用户端计算wa
 *
 * @param  ctx  [in]	密钥生成协议结构体
 * @param   w   [out]   生成的w
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_key_generate_W(sm2_mobile_key_context *ctx, mbedtls_ecp_point *w);

/**
 * 计算公钥的值，计算P_a
 *
 * @param  ctx  [in]	密钥生成协议结构体
 * @param   w   [in]    传输的w
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_key_generate_Pa(sm2_mobile_key_context *ctx,
		const mbedtls_ecp_point *w);

/**
 * 初始化用户结构体
 *
 * @param  ctx  [in]	用户结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_client_init(sm2_mobile_sign_client_context *ctx);

/**
 * 释放用户结构体资源
 *
 * @param  ctx  [in]	用户结构体
 *
 * @return    
 */
void sm2_mobile_sign_client_free(sm2_mobile_sign_client_context *ctx);

/**
 * 用户端生成P1,和P2
 *
 * @param  ctx  [in]	用户结构体
 * @param  P1   [out]   生成p1
 * @param  P2   [out]   生成p2
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_client_generate_first(sm2_mobile_sign_client_context *ctx,
		mbedtls_ecp_point *P1, mbedtls_ecp_point *P2);

/**
 * 用户端生成  σ 和 δ 
 *
 * @param  ctx  [in]	用户结构体
 * @param  Q1   [in]	服务器端的Q1
 * @param  Q2   [in]	服务器端的Q2
 * @param  id   [in]	用户id
 * @param  msg  [in]	签名消息
 * @param  x1   [out]   σ
 * @param  x2   [out]   δ
 * 
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_client_generate_second(sm2_mobile_sign_client_context *ctx,
		const mbedtls_ecp_point *Q1, const mbedtls_ecp_point *Q2,
		const char *id, const char *msg, mbedtls_mpi *x1, mbedtls_mpi *x2);

/**
 * 用户端生成一个完整的sm2签名
 *
 * @param  ctx  [in]	用户结构体
 * @param  x1   [in]	服务器端的 σs
 * @param  x2   [in]	服务器端的 δs
 * @param  out 	[out]	签名值（2进制表示）(r|s)
 *
 * @return    		 [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_client_generate_third(sm2_mobile_sign_client_context *ctx,
		const mbedtls_mpi *x1, const mbedtls_mpi *x2, const char *id,
		const char *msg, unsigned char out[64]);

/**
 * 初始服务器端结构体
 *
 * @param  ctx  [in]	服务器端结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_server_init(sm2_mobile_sign_server_context *ctx);

/**
 * 释放服务器端结构体
 *
 * @param  ctx  [in]	服务器端结构体
 *
 * @return     
 */
void sm2_mobile_sign_server_free(sm2_mobile_sign_server_context *ctx);

/**
 * 初始服务器端生成Q1和Q2
 *
 * @param  ctx  [in]	服务器端结构体
 * @param  Q1   [out]	服务器端的Q1
 * @param  Q2   [out]	服务器端的Q2
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_server_generate_first(sm2_mobile_sign_server_context *ctx,
		mbedtls_ecp_point *Q1, mbedtls_ecp_point *Q2);

/**
 * 初始服务器端生成 σ 和 δ
 *
 * @param  ctx  [in]	服务器端结构体
 * @param  x1   [in]	客户端的 σa
 * @param  x2   [in]	客户端的 δa
 * @param  id   [in]	用户id
 * @param  msg  [in]	签名消息
 * @param  xx1  [out]	服务器端的 σs
 * @param  xx2  [out]	服务器端的 δs
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_server_generate_second(sm2_mobile_sign_server_context *ctx,
		const mbedtls_mpi *x1, const mbedtls_mpi *x2, const char *id,
		const char *msg, mbedtls_mpi *xx1, mbedtls_mpi *xx2);

/**
 * 验证sm2签名
 *
 * @param  key   [in]	含有公钥的上下文
 * @param  id    [in]	id
 * @param  msg   [in]	消息
 * @param  dsgt  [in]	摘要值(二进制值)
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_sign_verify(sm2_mobile_key_context *key, const char *id,
		const char *message, const unsigned char *dgst, const size_t dgstlen);

/**
 * 设置椭圆曲线参数，通过16进制字符串,如“126AFEFFF”
 *
 * @param  grp  [out]	 椭圆曲线域
 * @param  p     [in]    p hex string buffer
 * @param  a     [in]    a hex string buffer 
 * @param  b     [in]    b hex string buffer 
 * @param  gx    [in]    gx hex string buffer 
 * @param  gy    [in]    gy hex string buffer 
 * @param  n     [in]    n hex string buffer 
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_set_group_by_hex(mbedtls_ecp_group *grp, const char *p,
		const char *a, const char *b, const char *gx, const char *gy,
		const char *n);

/**
 * 设置椭圆曲线参数，通过2进制数组,大端
 *
 * @param  grp  [out]	 椭圆曲线域
 * @param  p     [in]    p  
 * @param  a     [in]    a   
 * @param  b     [in]    b   
 * @param  gx    [in]    gx  
 * @param  gy    [in]    gy  
 * @param  n     [in]    n   
 * @param  len   [in]    p,b,a,gx,gy,n是等长的数组，因此只需要传入一个数组长度即可。
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_set_group_by_binary(mbedtls_ecp_group *grp,
		const unsigned char *p, const unsigned char *a, const unsigned char *b,
		const unsigned char *gx, const unsigned char *gy,
		const unsigned char *n, size_t len);

/**
 * mbedtls_mpi 数据转换16进制字符串格式
 *
 * @param  mpi  [in]	mbedtls_mpi 参数
 * @param  buf  [out]	mbedtls_mpi 16进制表示的buf
 * @param  len  [in]	buf 的本身长度
 * @param  olen [out]   16进制表示的buf有效长度
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_mpi2hex(const mbedtls_mpi *mpi, char *buf, size_t len, size_t *olen);

/**
 * mbedtls_mpi 数据转换2进制数组格式，大端
 *
 * @param  mpi  [in]	mbedtls_mpi 参数
 * @param  buf  [out]	mbedtls_mpi 2进制表示的buf
 * @param  len  [in]	buf 的本身长度
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_mpi2binary(const mbedtls_mpi *mpi, unsigned char *buf, int len);

/**
 * mbedtls_ecp_point 数据转换16进制字符串格式
 *
 * @param  p     [in]	mbedtls_ecp_point 参数
 * @param  bufx  [out]	mbedtls_ecp_point 16进制表示的buf。其中bufx = x。
 * @param  lenx  [in]	bufx 的本身长度
 * @param  olenx [out]  16进制表示的bufx有效长度
 * @param  bufy  [out]	mbedtls_ecp_point 16进制表示的buf。其中bufy = y。
 * @param  leny  [in]	bufy的本身长度
 * @param  oleny [out]  16进制表示的bufy有效长度
 * @return       [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_point2hex(const mbedtls_ecp_point *p, char *bufx, size_t lenx,
		size_t *olenx, char *bufy, size_t leny, size_t *oleny);

/**
 * mbedtls_ecp_point 数据转换2进制数组格式，大端
 *
 * @param  p     [in]	mbedtls_ecp_point 参数
 * @param  bufx  [out]	mbedtls_ecp_point 2进制表示的buf。其中bufx = x。
 * @param  lenx  [in]	bufx 的本身长度
 * @param  bufy  [out]	mbedtls_ecp_point 2进制表示的buf。其中bufy = x。
 * @param  leny  [in]	bufy 的本身长度
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_point2binary(const mbedtls_ecp_point *p, unsigned char *bufx,
		size_t lenx, unsigned char *bufy, size_t leny);

/**
 * 16进制格式 转换 mbedtls_mpi 数据
 *
 * @param  buf  [in]	mbedtls_mpi 16进制表示的字符串，如“FFF12AE”
 * @param  mpi  [out]	mbedtls_mpi 参数
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_hex2mpi(const char *buf, mbedtls_mpi *mpi);

/**
 * 2进制格式 转换 mbedtls_mpi 数据,大端
 *
 * @param  buf  [in]	mbedtls_mpi 2进制表示的数组
 * @param  len  [in]	buf 的本身长度
 * @param  mpi  [out]	mbedtls_mpi 参数
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_binary2mpi(const unsigned char *buf, int len, mbedtls_mpi *mpi);

/**
 * mbedtls_ecp_point 数据转换16进制字符串格式，如“FFF12AE”
 *
 * @param  bufx  [in]	mbedtls_ecp_point 16进制表示的buf。其中bufx = x。
 * @param  bufy  [in]	mbedtls_ecp_point 16进制表示的buf。其中bufy = y。
 * @param  p    [out]	mbedtls_ecp_point 参数
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_hex2point(const char *bufx, const char *bufy,
		mbedtls_ecp_point *p);

/**
 * 2进制格式 转换 mbedtls_ecp_point 数据,大端
 *
 * @param  bufx  [in]	mbedtls_ecp_point 2进制表示的数组。其中bufx = x。
 * @param  lenx  [in]	bufx 的本身长度
 * @param  bufy  [in]	mbedtls_ecp_point 2进制表示的数组。其中bufy = y。
 * @param  leny  [in]	bufy 的本身长度
 * @param  p    [out]	mbedtls_ecp_point 参数
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_binary2point(const unsigned char *bufx, int lenx,
		const unsigned char *bufy, int leny, mbedtls_ecp_point *p);

/**
 * mbedtls_mpi 复制函数 ;
 *
 * @param  mpi  [in]	需要被拷贝的参数
 * @param  dst  [out]	拷贝结果
 *
 * @return      [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_mpi_copy(const mbedtls_mpi *mpi, mbedtls_mpi *dst);

/**
 * mbedtls_ecp_point 复制函数 ;
 *
 * @param  p  	[in]	需要被拷贝的参数
 * @param  dst  [out]	拷贝结果
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_mobile_point_copy(const mbedtls_ecp_point *p, mbedtls_ecp_point *dst);

/**
 * 设置服务器端 P1 和P2 参数
 * @param  ctx  	[out]	服务端context
 * @param  P1       [in]    参数P1
 * @param  P2       [in]    参数P2
 */
int sm2_mobile_sign_server_set_P(sm2_mobile_sign_server_context *ctx,
		const mbedtls_ecp_point *P1, const mbedtls_ecp_point *P2);


/**
 * 设置服务器端密钥参数
 * @param  ctx  	[out]	服务端context
 * @param  key      [in]    密钥参数
 *
 */
int sm2_mobile_sign_server_set_key(sm2_mobile_sign_server_context *ctx,
		const sm2_mobile_key_context *key);

/**
 * 设置客户端端密钥参数
 * @param  ctx  	[out]	客户端context
 * @param  key      [in]    密钥参数
 *
 */
int sm2_mobile_sign_client_set_key(sm2_mobile_sign_client_context *ctx,
		const sm2_mobile_key_context *key);


/**
 * 签名测试函数
 */
int sm2_mobile_sign_test();
#ifdef __cplusplus
}
#endif

#endif 
