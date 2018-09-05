/**
 * author  lzj
 *
 * create 2018.5.15
 *
 * sm2 mobile signature transform to json
 *
 *
 */

#ifndef CSERIALIZABLE_H
#define CSERIALIZABLE_H

#include <stdio.h>
#include <AisinoSSL/sm2/cJSON.h>
#include <AisinoSSL/sm2/sm2_mobile_signature.h>
#include <string.h>

// mpi json 键
#define CSE_MPI_X1 "x1"
#define CSE_MPI_X2 "x2"
#define CSE_MPI_XX1 "xx1"
#define CSE_MPI_XX2 "xx2"
#define CSE_MPI_MPI "mpi"

//point json 键
#define CSE_POINT_X "x"
#define CSE_POINT_Y "y"

//key   json 键
#define CSE_KEY_HD "hd"
#define CSE_KEY_PA "pa"

//client json 键
#define CSE_CLIENT_KEY "key"
#define CSE_CLIENT_P1 "p1"
#define CSE_CLIENT_P2 "p2"
#define CSE_CLIENT_U "u"
#define CSE_CLIENT_A1 "a1"
#define CSE_CLIENT_A2 "a2"
#define CSE_CLIENT_R "r"

//server json 键
#define CSE_SERVER_KEY "key"
#define CSE_SERVER_P1 "p1"
#define CSE_SERVER_P2 "p2"
#define CSE_SERVER_Q1 "Q1"
#define CSE_SERVER_Q2 "Q2"
#define CSE_SERVER_S1 "s1"
#define CSE_SERVER_S2 "s2"

/*错误代码*/
#define SERIALIZABLE_BUFFER_ERROR  -100  /*buffer length too short*/

#define SERIALIZABLE_JSON_ERROR_NULL  -101  /*create json failed */

#define SERIALIZABLE_JSON_ERROR_PRINTF  -102  /*printf json failed */

#define SERIALIZABLE_JSON_ERROR_PARSE  -103  /*parse json failed */

#define SERIALIZABLE_JSON_ERROR_PARSE_ITEM  -104  /*parse  json item failed */

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * json 转化为 mpi
 *
 * @param  mpi  		[out]	mpi 结构体
 * @param  pJsonRoot  	[in]    json上下文
 * @param  type  		[in]    json的键
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2mpi_type(mbedtls_mpi *mpi, const cJSON * pJsonRoot,
		const char* type);

/**
 * json 转化为 mpi 默认键为“mpi”
 *
 * @param  mpi  		[out]	mpi 结构体
 * @param  pJsonRoot  	[in]    json上下文
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2mpi(mbedtls_mpi *mpi, const cJSON * pJsonRoot);

/**
 * json 转化为 point
 *
 * @param  point  		[out]	point 结构体
 * @param  pJsonRoot  	[in]    json上下文
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2point(mbedtls_ecp_point *p, const cJSON * pJsonRoot);

/**
 * json 转化为 key
 *
 * @param  key  		[out]	key 结构体
 * @param  pJsonRoot  	[in]    json上下文
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2key(sm2_mobile_key_context *ctx,
		const cJSON * pJsonRoot);

/**
 * json 转化为 client
 *
 * @param  client  		[out]	client 结构体
 * @param  pJsonRoot  	[in]    json上下文
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2client(sm2_mobile_sign_client_context *ctx,
		const cJSON * pJsonRoot);

/**
 * json 转化为 server
 *
 * @param  server  		[out]	server 结构体
 * @param  pJsonRoot  	[in]    json上下文
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_json2server(sm2_mobile_sign_server_context *ctx,
		const cJSON * pJsonRoot);

/**
 * mpi 转化为 json
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  mpi			  	[in]    mpi结构体
 * @param  type			  	[in]    json的键
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */

int sm2_m_serializ_mpi2json_type(cJSON * pJsonRoot, const mbedtls_mpi *mpi,
		const char *type);

/**
 * mpi 转化为 json ,默认转化后的键为“mpi”
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  mpi			  	[in]    mpi结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_mpi2json(cJSON * pJsonRoot, const mbedtls_mpi *mpi);

/**
 * point 转化为 json
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  point			[in]    point结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_point2json(cJSON * pJsonRoot, const mbedtls_ecp_point *p);

/**
 * key 转化为 json
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  key				[in]    key结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_key2json(cJSON * pJsonRoot,
		const sm2_mobile_key_context *ctx);

/**
 * client 转化为 json
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  client			[in]    client结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_client2json(cJSON * pJsonRoot,
		const sm2_mobile_sign_client_context *ctx);

/**
 * server 转化为 json
 *
 * @param  pJsonRoot  		[out]	pJsonRoot上下文
 * @param  server			[in]    server结构体
 *
 * @return     [flag]	if successfully 0, otherwise failed.
 */
int sm2_m_serializ_server2json(cJSON * pJsonRoot,
		const sm2_mobile_sign_server_context *ctx);

/**
 * mpi 测试函数
 *
 * {
 * 		"mpi":	"0F"
 * }
 */
int sm2_m_serializable_test_mpi();

/**
 * point 测试函数
 *{
 *	"x":	"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
 *	"y":	"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
 *}
 *
 */
int sm2_m_serializable_test_point();

/**
 * key 测试函数
 * {
 *	"hd":	"0FFF",
 *	"pa":	{
 *		"x":	"85BF6F",
 *		"y":	"7873BB"
 *	    }
 * }
 */
int sm2_m_serializable_test_key();

/**
 * client 测试函数
 * {
 *	"key":	{
 *		"hd":	"0FFF",
 *		"pa":	{
 *			"x":	"85BF6F",
 *			"y":	"7873BB"
 *		}
 *	},
 *	"p1":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"p2":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"u":	"",
 *	"a1":	"",
 *	"a2":	"",
 *	"r":	""
 *}
 */
int sm2_m_serializable_test_client();

/**
 * server 测试函数
 * {
 *	"key":	{
 *		"hd":	"0FFF",
 *		"pa":	{
 *			"x":	"85BF6F",
 *			"y":	"7873BB"
 *		}
 *	},
 *	"p1":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"p2":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"Q1":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"Q2":	{
 *		"x":	"",
 *		"y":	""
 *	},
 *	"s1":	"",
 *	"s2":	""
 *}
 */
int sm2_m_serializable_test_server();

#ifdef __cplusplus
}
#endif
#endif
