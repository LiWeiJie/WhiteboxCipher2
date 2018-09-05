/*
 * @Author: Weijie Li 
 * @Date: 2017-11-27 16:32:03 
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2018-07-30 21:39:12
 */
#ifndef AISINOSSL_MATH_AFFINE_TRANSFORM_H_
#define AISINOSSL_MATH_AFFINE_TRANSFORM_H_

#include<AisinoSSL/math/matrix_gf2.h>

typedef struct AffineTransform {
    MatGf2 linear_map;
    MatGf2 vector_translation;
} AffineTransform;

int GenRandomAffineTransform(AffineTransform *at, AffineTransform *at_inv, int dim);

int GenIndAffineTransform(AffineTransform *at, AffineTransform *at_inv, int dim);

int ApplyAffineTransform(const AffineTransform at, const MatGf2 mat, MatGf2* dst);

uint32_t ApplyAffineToU32(const AffineTransform aff, uint32_t x);

uint16_t ApplyAffineToU16(const AffineTransform aff, uint16_t data);

uint8_t ApplyAffineToU8(const AffineTransform aff, uint8_t data);

int AffineTransformFree(AffineTransform *aff);

/**
 * @brief export AffineTransform to str
 * 
 * @param aff 
 * @return void* 
 */
uint8_t * ExportAffineToStr(const AffineTransform* aff);

/**
 * @brief import AffineTransform from str
 * 
 * @param source 
 * @return AffineTransform 
 */
AffineTransform ImportAffineFromStr(const uint8_t *source);

#endif /* AISINOSSL_MATH_AFFINE_TRANSFORM_H_ */