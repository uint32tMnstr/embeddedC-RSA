#ifndef _BIGNUM_H
#define _BIGNUM_H

#ifdef __cplusplus 
extern "C"{
#endif

#include <string.h>
#include "crsa_common.h"

#define CRSA_BN_CNT         (CRSA_CNT_U16 * 2)
#define CRSA_BN_BUF_CNT     (sizeof(BN_T) + CRSA_CNT_U16)

#define BN_PRINT(_pbn)                                     \
    {                                                      \
        LOG("%s(%d): ", __FUNCTION__, __LINE__);         \
        if ((_pbn)->cnt < 0)                               \
            LOG("ERR: %d\r\n", (_pbn)->cnt);               \
        else                                               \
            LOG_SHORT("BN", (_pbn)->val, (_pbn)->cnt); \
    }

#define BN_TYPE(_bn)            ((BN_T *)_bn)
#define BN_CNST_TYPE(_bn)       ((const  BN_T *)_bn)
#define BN_IS_NOT_EMPTY(_bn)    (_bn && _bn->cnt > 0 && _bn->val[_bn->cnt - 1])
#define BN_IS_ZERO(_bn)         (!BN_IS_NOT_EMPTY(_bn))
#define BN_SET_CNT(_bn)                                                        \
    for (_bn->cnt = _bn->maxcnt; _bn->cnt && !_bn->val[_bn->cnt - 1]; --_bn->cnt) \
        ;
#define BN_ZERO(_bn, _idx)                                                    \
    {                                                                         \
        if ((int16_t)(_idx) < _bn->maxcnt)                                               \
            memset(&_bn->val[_idx], 0, sizeof(uint16_t) * (_bn->maxcnt - (int16_t)(_idx))); \
        BN_SET_CNT(_bn)                                                       \
    }
#define BN_DEFINE(_bn, _cnt, _array...)                             \
    uint16_t _buf_##_bn[sizeof(BN_T) + _cnt] = {0, _cnt, };         \
    BN_T * _bn = (BN_T *)_buf_##_bn;                                 \
    {                                                               \
        const uint16_t _val_##_bn[] = {_array};                      \
        _bn->cnt = MIN(sizeof(_val_##_bn) / sizeof(uint16_t), _cnt); \
        memcpy(_bn->val, _val_##_bn, sizeof(uint16_t) * _bn->cnt);   \
        BN_ZERO(_bn, _bn->cnt)                                      \
    }
#define BN_COPY(_dst, _src)                                             \
    {                                                                   \
        if (_dst != _src)                                               \
        {                                                               \
            _dst->cnt = MIN(_src->cnt, _dst->maxcnt);                   \
            memcpy(_dst->val, _src->val, sizeof(uint16_t) * _dst->cnt); \
            BN_ZERO(_dst, _dst->cnt)                                    \
        }                                                               \
    }
#define BN_RST(_bn)                                          \
    {                                                        \
        _bn->cnt = 0;                                        \
        memset(_bn->val, 0, sizeof(uint16_t) * _bn->maxcnt); \
    }
#define BN_FMT(_bn, _idx)   BN_ZERO(_bn, _idx)

typedef uint16_t BIGNUM_T;  //运算单位

typedef struct _BN_T{
    int16_t cnt;    //大数占用的实际个数
    int16_t maxcnt; //数组的最大个数
    uint16_t val[0];
}BN_T;

int16_t bn_init(void);

BOOL bn_cmp_e(const BN_T *src, const BN_T *ref);
BOOL bn_cmp_l(const BN_T *src, const BN_T *ref);
BOOL bn_cmp_le(const BN_T *src, const BN_T *ref);
BOOL bn_cmp_b(const BN_T *src, const BN_T *ref);
BOOL bn_cmp_be(const BN_T *src, const BN_T *ref);

void bn_add_num(const BN_T *src, const uint16_t num, BN_T *dst);
void bn_minus_num(const BN_T *src, const uint16_t num, BN_T *dst);
void bn_mult_num(const BN_T *src, const uint16_t num, BN_T *dst);
void bn_devide_num(const BN_T *src, const uint16_t num, BN_T *dst);

void bn_add(const BN_T *src1, const BN_T *src2, BN_T *dst);
void bn_minus(const BN_T *src1, const BN_T *src2, BN_T *dst);
void bn_mult(const BN_T *src1, const BN_T *src2, BN_T *dst);
// TODO: void bn_devide(const BN_T *src1, const BN_T *src2, BN_T *dst);

void bn_mod(const BN_T *src, const BN_T *modulus, BN_T *dst);
void bn_modexp(const BN_T *src, const BN_T *exp, const BN_T *mod, BN_T *dst);

#ifdef __cplusplus
};
#endif

#endif  //_BIGNUM_H