#ifndef _BIGNUM_H
#define _BIGNUM_H

#include <string.h>
#include <stdint.h>
#include "crsa_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LOGBN(...) //LOG(__VA_ARGS__)

#define __OPT_64
#ifdef __OPT_64
    typedef uint64_t maxunit_t;
    typedef uint32_t opt_num_t;
#else
typedef uint32_t maxunit_t;
typedef uint16_t opt_num_t;
#endif
    typedef int16_t BN_RET_T;
    typedef int16_t BN_CNT_T;
    typedef uint16_t BN_UNIT_T;

#define BN_PTR(_bn) ((BN_T *)(_bn))
#define BN_CNT(_cnt) ((BN_CNT_T)(_cnt))
#define CNST_BN_PTR(_bn) ((const BN_T *)(_bn))
#define CNST_BN_CNT(_cnt) ((const BN_CNT_T)(_cnt))

#define VAL_OF_OPT(_p) (*((opt_num_t *)(_p)))
#define VAL_OF_MAX_UNIT(_p) (*((maxunit_t *)(_p)))

#define BITS_OF_BYTE 8

#define BITS_OF_BN_VAL (sizeof(BN_UNIT_T) * BITS_OF_BYTE)
#define BYTE_OF_BN_VAL (CRSA_KEY_BITS / BITS_OF_BYTE)
#define CNT_OF_BN_VAL (BYTE_OF_BN_VAL / sizeof(BN_UNIT_T))
#define CNT_OF_BN_BUF ((sizeof(BN_T) + sizeof(BN_UNIT_T) - 1) / sizeof(BN_UNIT_T) + CNT_OF_BN_VAL)
#define MAX_VAL_OF_BN_UNIT ((BN_UNIT_T)-1)

#define BITS_OF_OPT (sizeof(opt_num_t) * BITS_OF_BYTE)
#define CNT_OF_OPT (sizeof(opt_num_t) / sizeof(BN_UNIT_T))
#define MAX_VAL_OF_OPT ((opt_num_t)-1)

#define BITS_OF_MAX_UNIT (sizeof(maxunit_t) * BITS_OF_BYTE)
#define CNT_OF_MAX_UNIT (sizeof(maxunit_t) / sizeof(BN_UNIT_T))
#define MAX_VAL_OF_MAX_UNIT ((maxunit_t)-1)


// #define MEMCPY(_dst, _src, _size)   {if(_size) MEMCPY(_dst, _src, _size);}
// #define MEMSET(_dst, _val, _size)   {if(_size) MEMSET(_dst, _val, _size);}
#define MEMCPY memcpy
#define MEMSET memset

#define BASE_BN_PRINT(_bn)                                                           \
    {                                                                                \
        LOG("%s(%d): ", __FUNCTION__, __LINE__);                                     \
        if (_bn->cnt & CRSA_EC_BIT_MASK)                                             \
            LOG("ERR: 0x%04X\r\n", _bn->cnt);                                        \
        else                                                                         \
        {                                                                            \
            LOG("BN[%d]: ", _bn->maxcnt);                                            \
            LOG_SHORT("", (const uint16_t *)_bn->val, _bn->cnt);                      \
            /*LOG("BN[%d]: ", _bn->maxcnt * sizeof(BN_UNIT_T));                      \
            LOG_BYTE("", (const uint8_t *)_bn->val, _bn->cnt * sizeof(BN_UNIT_T));*/ \
        }                                                                            \
    }
#define BASE_BN_CHECK(_bn)                \
    FASSERT(                              \
        _bn &&                            \
        !(_bn->cnt & CRSA_EC_BIT_MASK) && \
        _bn->cnt <= _bn->maxcnt &&        \
        _bn->maxcnt > 0 &&                \
        (!_bn->cnt || _bn->val[_bn->cnt - 1]))
#define BASE_BN_SET_CNT(_bn, _ref_pos)                                                               \
    {                                                                                                \
        for (_bn->cnt = MIN(_ref_pos, _bn->maxcnt);                                                  \
             _bn->cnt >= CNT_OF_MAX_UNIT && !VAL_OF_MAX_UNIT(_bn->val + _bn->cnt - CNT_OF_MAX_UNIT); \
             _bn->cnt -= CNT_OF_MAX_UNIT)                                                            \
            ;                                                                                        \
        for (; _bn->cnt && !_bn->val[_bn->cnt - 1]; --_bn->cnt)                                      \
            ;                                                                                        \
    }
#define BASE_BN_ZERO(_bn, _ref_pos)                                                       \
    {                                                                                     \
        if (_ref_pos < _bn->maxcnt)                                                       \
            MEMSET(&_bn->val[_ref_pos], 0, sizeof(BN_UNIT_T) * (_bn->maxcnt - _ref_pos)); \
        BASE_BN_SET_CNT(_bn, _ref_pos)                                                    \
    }
#define BASE_BN_COPY(_dst, _src)                                                             \
    {                                                                                        \
        if (_dst->maxcnt > _src->cnt)                                                        \
        {                                                                                    \
            _dst->cnt = _src->cnt;                                                           \
            MEMCPY(_dst->val, _src->val, sizeof(BN_UNIT_T) * _dst->cnt);                     \
            MEMSET(&_dst->val[_dst->cnt], 0, sizeof(BN_UNIT_T) * (_dst->maxcnt - _dst->cnt)); \
        }                                                                                    \
        else                                                                                 \
        {                                                                                    \
            MEMCPY(_dst->val, _src->val, sizeof(BN_UNIT_T) * _dst->maxcnt);                  \
            BASE_BN_SET_CNT(_dst, _dst->maxcnt);                                             \
        }                                                                                    \
    }
#define BASE_BN_RST(_bn)                                      \
    {                                                         \
        _bn->cnt = 0;                                         \
        MEMSET(_bn->val, 0, sizeof(BN_UNIT_T) * _bn->maxcnt); \
    }
#define BASE_BN_DEFINE(_bn, _cnt)                                                                  \
    BN_UNIT_T _buf_##_bn[(sizeof(BN_T) + sizeof(BN_UNIT_T) - 1) / sizeof(BN_UNIT_T) + _cnt] = {0}; \
    BN_T *_bn = (BN_T *)_buf_##_bn;                                                                \
    _bn->maxcnt = _cnt;

#define BN_DEFINE(_bn, _cnt, ...)                                                                  \
    BN_UNIT_T _buf_##_bn[(sizeof(BN_T) + sizeof(BN_UNIT_T) - 1) / sizeof(BN_UNIT_T) + _cnt] = {0}; \
    BN_T *_bn = (BN_T *)_buf_##_bn;                                                                \
    {                                                                                              \
        const BN_UNIT_T _val_##_bn[] = {0, __VA_ARGS__};                                           \
        const BN_CNT_T _val_size_##_bn = MIN(sizeof(_val_##_bn) / sizeof(BN_UNIT_T) - 1, _cnt);    \
        if (_val_size_##_bn)                                                                       \
            MEMCPY(_bn->val, &_val_##_bn[1], sizeof(BN_UNIT_T) * _val_size_##_bn);                 \
        _bn->maxcnt = _cnt;                                                                        \
        BASE_BN_SET_CNT(_bn, _val_size_##_bn)                                                      \
    }
#define BN_PRINT(_bn) BASE_BN_PRINT(CNST_BN_PTR(_bn))
//校验BN的正确性
#define BN_CHECK(_bn) BASE_BN_CHECK(CNST_BN_PTR(_bn))
#define BN_NOT_EMPTY(_bn) (CNST_BN_PTR(_bn)->cnt)
#define BN_EMPTY(_bn) (!BN_NOT_EMPTY(_bn))
#define BN_SET_CNT(_bn) BASE_BN_SET_CNT(BN_PTR(_bn), BN_PTR(_bn)->maxcnt)
#define BN_SET_CNT_EX(_bn, _ref_pos) BASE_BN_SET_CNT(BN_PTR(_bn), CNST_BN_CNT(_ref_pos))
#define BN_CLEAR(_bn, _ref_pos) BASE_BN_ZERO(BN_PTR(_bn), CNST_BN_CNT(_ref_pos))
#define BN_COPY(_dst, _src)                \
    if (BN_PTR(_dst) != CNST_BN_PTR(_src)) \
        BASE_BN_COPY(BN_PTR(_dst), CNST_BN_PTR(_src))
#define BN_RST(_bn) BASE_BN_RST(BN_PTR(_bn))

    typedef struct _BN_T
    {
        BN_CNT_T cnt;    //大数占用的实际个数
        BN_CNT_T maxcnt; //数组的最大个数
        BN_UNIT_T val[0];
    } BN_T;

    BN_RET_T bn_init(void);
    BOOL bn_cmp_e(const BN_T *src, const BN_T *ref);
    BOOL bn_cmp_l(const BN_T *src, const BN_T *ref);
    BOOL bn_cmp_le(const BN_T *src, const BN_T *ref);
    BOOL bn_cmp_b(const BN_T *src, const BN_T *ref);
    BOOL bn_cmp_be(const BN_T *src, const BN_T *ref);

    void bn_add_num(const BN_T *src, const opt_num_t num, BN_T *dst);
    void bn_minus_num(const BN_T *src, const opt_num_t num, BN_T *dst);
    void bn_mult_num(const BN_T *src, const opt_num_t num, BN_T *dst);
    void bn_devide_num(const BN_T *src, const opt_num_t num, BN_T *dst);

    void bn_add(const BN_T *src1, const BN_T *src2, BN_T *dst);
    void bn_minus(const BN_T *src1, const BN_T *src2, BN_T *dst);
    void bn_mult(const BN_T *src1, const BN_T *src2, BN_T *dst);
    // TODO: void bn_devide(const BN_T *src1, const BN_T *src2, BN_T *dst);

    void bn_mod(const BN_T *src, const BN_T *modulus, BN_T *dst);
    void bn_modexp(const BN_T *src, const BN_T *exp, const BN_T *mod, BN_T *dst);
    void bn_shift_l(const BN_T *src, uint16_t shift_bits, BN_T *dst);

#ifdef __cplusplus
};
#endif

#endif //_BIGNUM_H