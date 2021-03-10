#include <string.h>
#include "crsa_common.h"
#include "bignum.h"

#define BN_IS_VALID(_bn)        (_bn && _bn->cnt >= 0 && _bn->cnt <= _bn->maxcnt && _bn->maxcnt > 0 && (!_bn->cnt || _bn->val[_bn->cnt - 1]))
#define BN_CMP_BASE(_src, _opt, _ref)                                       \
    {                                                                       \
        FASSERT(BN_IS_VALID(_src))                                          \
        FASSERT(BN_IS_VALID(_ref))                                          \
        if (_src->cnt && _src->cnt == _ref->cnt) {                          \
            int16_t i;                                                      \
            for (i = _src->cnt - 1; i && _src->val[i] == _ref->val[i]; --i) \
                ;                                                           \
            return (_src->val[i] _opt _ref->val[i]);                        \
        }                                                                   \
        return (_src->cnt _opt _ref->cnt);                                  \
    }
BOOL bn_cmp_e(const BN_T *src, const BN_T *ref)  BN_CMP_BASE(src, ==, ref)
BOOL bn_cmp_l(const BN_T *src, const BN_T *ref)  BN_CMP_BASE(src, <, ref)
BOOL bn_cmp_le(const BN_T *src, const BN_T *ref) BN_CMP_BASE(src, <=, ref)
BOOL bn_cmp_b(const BN_T *src, const BN_T *ref)  BN_CMP_BASE(src, >, ref)
BOOL bn_cmp_be(const BN_T *src, const BN_T *ref) BN_CMP_BASE(src, >=, ref)

void bn_add_num(const BN_T *src, const uint16_t num, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(dst && dst->maxcnt > 0)
    
    uint32_t tmp = num;
    int16_t i, maxcnt;

    maxcnt = MIN(src->maxcnt, dst->maxcnt);
    for(i = 0; tmp && i < maxcnt; ++i){
        tmp += (uint32_t)src->val[i];
        dst->val[i] = tmp;
        tmp >>= CRSA_UNIT_BITS;
    }

    if(src == dst){
        i = MAX(i, src->cnt);
    } else if(tmp && i < dst->maxcnt){
        FASSERT(i == src->maxcnt)
        dst->val[i] = tmp;
        ++i;
    }else if (i < dst->maxcnt){
        maxcnt = MIN(MAX(i, src->cnt), dst->maxcnt);
        if(i < maxcnt){
            memcpy(&dst->val[i], &src->val[i], sizeof(uint16_t) * (maxcnt - i));
            i = maxcnt;
        }
    }
    BN_FMT(dst, i);
}
void bn_minus_num(const BN_T *src, const uint16_t num, BN_T *dst){
    // 忽略下溢
    FASSERT(BN_IS_VALID(src))
    FASSERT(dst && dst->maxcnt > 0)
    
    int16_t i, maxcnt, brw_flag, brw_flag_last;

    maxcnt = MIN(src->maxcnt, dst->maxcnt);
    brw_flag = (src->val[0] < num) ? 1 : 0;
    dst->val[0] = src->val[0] - num;
    for(i = 1; brw_flag && i < maxcnt; ++i){
        brw_flag = src->val[i] ? 0 : 1;
        dst->val[i] = src->val[i] - 1;
    }

    if (src == dst){
        i = MAX(i, src->cnt);
    } else if (brw_flag && i < dst->maxcnt){    // 若src下溢但dst未下溢，使dst下溢
        FASSERT(i == src->maxcnt)
        memset(&dst->val[i], 0xFF, sizeof(uint16_t) * (dst->maxcnt - i));
        i = dst->maxcnt;
    } else if (i < dst->maxcnt){    // 未下溢
        maxcnt = MIN(MAX(i, src->cnt), dst->maxcnt);
        if(i < maxcnt){
            memcpy(&dst->val[i], &src->val[i], sizeof(uint16_t) * (maxcnt - i));
            i = maxcnt;
        }
    }
    BN_FMT(dst, i);
    // FASSERT(!brw_flag) //禁止下溢
}
void bn_mult_num(const BN_T *src, const uint16_t num, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(dst && dst->maxcnt > 0)

    uint32_t tmp = 0;
    int16_t i = 0, maxcnt;

    maxcnt = MIN(src->cnt, dst->maxcnt);
    for(i = 0; i < maxcnt; ++i){
        tmp += (uint32_t)num * (uint32_t)src->val[i];
        dst->val[i] = tmp;
        tmp >>= CRSA_UNIT_BITS;
    }

    if(tmp && i < dst->maxcnt){
        dst->val[i] = tmp;
        ++i;
    }
    BN_FMT(dst, i)
    // FASSERT(!tmp)    //禁止上溢
}
void bn_devide_num(const BN_T *src, const uint16_t num, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(dst && dst->maxcnt > 0)
    FASSERT(num)

    int16_t i = 0, maxcnt;
    uint16_t remainder = 0, remainder_last = 0;
    uint32_t tmp = 0;

    maxcnt = MIN(src->cnt, dst->maxcnt);
    for(i = src->cnt; i; --i){
        remainder = (tmp + src->val[i - 1]) % num;
        if(i <= maxcnt)
            dst->val[i - 1] = (tmp + src->val[i - 1]) / num;
        tmp = ((uint32_t)remainder)<<16;
    }
    if(maxcnt < dst->maxcnt)
        memset(&dst->val[maxcnt], 0, sizeof(uint16_t) * (dst->maxcnt - maxcnt));
    BN_SET_CNT(dst)
}

void bn_add(const BN_T *src1, const BN_T *src2, BN_T *dst){
    FASSERT(BN_IS_VALID(src1))
    FASSERT(BN_IS_VALID(src2))
    FASSERT(dst && dst->maxcnt > 0)

    const BN_T *big_src;
    uint32_t tmp = 0;
    uint16_t i = 0, maxcnt;

    maxcnt = MIN(MIN(src1->cnt, src2->cnt), dst->maxcnt);
    for(i = 0; i < maxcnt; ++i){
        tmp += (uint32_t)src1->val[i] + (uint32_t)src2->val[i];
        dst->val[i] = tmp;
        tmp >>= CRSA_UNIT_BITS;
    }
    if(i < dst->maxcnt){
        big_src = (src1->cnt > src2->cnt)? src1: src2;
        maxcnt = MIN(big_src->cnt, dst->maxcnt);
        for(; i < maxcnt; ++i){
            tmp += (uint32_t)big_src->val[i];
            dst->val[i] = tmp;
            tmp >>= CRSA_UNIT_BITS;
        }
        if(tmp && i < dst->maxcnt){
            dst->val[i] = tmp;
            ++i;
        }
    }
    BN_FMT(dst, i)
}
void bn_minus(const BN_T *src1, const BN_T *src2, BN_T *dst){
    FASSERT(BN_IS_VALID(src1))
    FASSERT(BN_IS_VALID(src2))
    FASSERT(dst && dst->maxcnt > 0)

    uint16_t i, maxcnt;
    uint16_t brw_flag = 0, brw_flag_last; //防止((dst == src1)||(dst == src2))为真出现借位问题

    maxcnt = MIN(MIN(src1->cnt, src2->cnt), dst->maxcnt);
    for(i = 0; i < maxcnt; ++i){
        brw_flag_last = brw_flag;
        brw_flag = (src1->val[i] < src2->val[i] + brw_flag_last)? 1: 0;
        dst->val[i] = src1->val[i] - src2->val[i] - brw_flag_last;
    }
    if(i < dst->maxcnt){
        if(src1->cnt > src2->cnt){
            maxcnt = MIN(src1->cnt, dst->maxcnt);
            for(; i < maxcnt; ++i){
                brw_flag_last = brw_flag;
                brw_flag = src1->val[i]? 0: 1;
                dst->val[i] = src1->val[i] - brw_flag_last;
            }
            FASSERT(!brw_flag)
        }else if(src1->cnt < src2->cnt){
            maxcnt = MIN(src2->cnt, dst->maxcnt);
            for(; i < maxcnt; ++i)
                dst->val[i] = (uint16_t)(-1) - (uint16_t)src2->val[i];
            
        }
        if(brw_flag && i < dst->maxcnt){
            memset(&dst->val[i], 0xFF, sizeof(uint16_t) * (dst->maxcnt - i));
            i = dst->maxcnt;
        }
    }
    BN_FMT(dst, i)
}

static void bn_mult_base_fft(const uint16_t *poly, const uint16_t coe, uint16_t *output){  //O(nlogn)
    //TODO:
}
static void bn_mult_base_normal(const BN_T *src1, const BN_T *src2, BN_T *dst){   //O(n^2)
    FASSERT(BN_IS_VALID(src1))
    FASSERT(BN_IS_VALID(src2))
    FASSERT(dst && dst->maxcnt > 0)


    uint32_t tmp;
    int16_t i, j = 0/* 必须初始化，src2为0 */;
    BN_DEFINE(pOut, CRSA_BN_CNT)

    if(bn_cmp_l(src1, src2)){
        const BN_T *exchg = src1;
        src1 = src2;
        src2 = exchg;
    }
    FASSERT(src1->cnt + src2->cnt - ((((uint32_t)src1->val[src1->cnt - 1] * (uint32_t)src2->val[src2->cnt - 1])>>16)? 0: 1) <= pOut->maxcnt)
    for(i = 0; i < src2->cnt; ++i){
        tmp = 0;
        for(j = 0; j < src1->cnt; ++j){
            tmp = tmp + (uint32_t)src2->val[i] * (uint32_t)src1->val[j] + (uint32_t)pOut->val[i + j];
            pOut->val[i + j] = tmp;
            tmp >>= CRSA_UNIT_BITS;
        }
        pOut->val[i + j] = tmp;
        ++j;
    }
    pOut->cnt = i + j + (pOut->val[i + j]? 1: 0);
    BN_FMT(pOut, pOut->cnt)
    BN_COPY(dst, pOut);
}
void bn_mult(const BN_T *src1, const BN_T *src2, BN_T *dst){
    bn_mult_base_normal(src1, src2, dst);
}

static void bn_mod_base(const BN_T *src, const BN_T *modulus, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(BN_IS_VALID(modulus))
    FASSERT(dst && dst->maxcnt == src->maxcnt) //不支持取余溢出

    BN_COPY(dst, src);

    while(bn_cmp_be(dst, modulus)){
        bn_minus(dst, modulus, dst);
        //根据modulus的最高位来加减
    }
}

uint16_t bn_bits(const BN_T *pbn){
    FASSERT(BN_IS_VALID(pbn))

    uint16_t val, shift_bits = 0;

    if(pbn->cnt){
        val = pbn->val[pbn->cnt - 1];
        FASSERT(val)
        for(shift_bits = CRSA_UNIT_BITS - 1; shift_bits && !(val>>shift_bits); --shift_bits)
            ;
        shift_bits += (pbn->cnt - 1) * CRSA_UNIT_BITS + 1;
    }

    return shift_bits;
}

void bn_shift_l(const BN_T *src, uint16_t shift_bits, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(dst && dst->maxcnt >= ((uint32_t)bn_bits(src) + (uint32_t)shift_bits + CRSA_UNIT_BITS - 1) / CRSA_UNIT_BITS)


    uint16_t shift_cnt, i, maxcnt;
    BN_DEFINE(pOut, CRSA_BN_CNT)

    shift_cnt = shift_bits / CRSA_UNIT_BITS;
    shift_bits %= CRSA_UNIT_BITS;
    
    if(shift_bits){
        uint32_t tmp = 0;
        maxcnt = MIN(src->cnt, dst->maxcnt - shift_cnt);
        for(i = 0; i < maxcnt; ++i){
            tmp |= (((uint32_t)src->val[i])<<shift_bits);
            pOut->val[i + shift_cnt] = tmp;
            tmp >>= CRSA_UNIT_BITS;
        }
        i += shift_cnt;
        if(tmp && i < dst->maxcnt){
            pOut->val[i] = tmp;
            ++i;
        }
        pOut->cnt = i;
    } else {
        maxcnt = MIN(src->cnt, dst->maxcnt - shift_cnt);
        // memset(pOut->val, 0, sizeof(uint16_t) * shift_cnt);
        memcpy(&pOut->val[shift_cnt], src->val, sizeof(uint16_t) * maxcnt);
        pOut->cnt = shift_cnt + maxcnt;
    }
    BN_FMT(pOut, pOut->cnt);
    BN_COPY(dst, pOut);
}
void bn_modulus_align(const BN_T *src, const BN_T *ref, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(BN_IS_VALID(ref))
    FASSERT(BN_IS_NOT_EMPTY(src))
    FASSERT(BN_IS_NOT_EMPTY(ref))
    FASSERT(dst && dst->maxcnt >= ref->cnt)


    int16_t i, maxcnt;
    uint16_t shift_bits, shift_cnt;

    BN_DEFINE(pOut, CRSA_BN_CNT)    //避免 dst = src

    if(bn_cmp_be(src, ref)){
        BN_COPY(dst, src)
        return;
    }

    shift_bits = bn_bits(ref) - bn_bits(src);
    shift_cnt = shift_bits / CRSA_UNIT_BITS;
    shift_bits %= CRSA_UNIT_BITS;

    if(shift_bits){
        uint32_t tmp = 0;
        maxcnt = MIN(src->cnt, dst->maxcnt - shift_cnt);
        for(i = 0; i < maxcnt; ++i){
            tmp |= (((uint32_t)src->val[i])<<shift_bits);
            pOut->val[i + shift_cnt] = tmp;
            tmp >>= CRSA_UNIT_BITS;
        }
        i += shift_cnt;
        if(tmp && i < dst->maxcnt){
            pOut->val[i] = tmp;
            ++i;
        }
        pOut->cnt = i;
    } else {
        maxcnt = MIN(src->cnt, dst->maxcnt - shift_cnt);
        // memset(pOut->val, 0, sizeof(uint16_t) * shift_cnt);
        memcpy(&pOut->val[shift_cnt], src->val, sizeof(uint16_t) * maxcnt);
        pOut->cnt = shift_cnt + maxcnt;
    }
    BN_FMT(pOut, pOut->cnt)
    if(bn_cmp_b(pOut, ref))
        bn_devide_num(pOut, 2, pOut);
    BN_COPY(dst, pOut);
}

void bn_mod(const BN_T *src, const BN_T *modulus, BN_T *dst){
    FASSERT(BN_IS_VALID(src))
    FASSERT(BN_IS_NOT_EMPTY(modulus))
    FASSERT(dst)

    BN_DEFINE(pOut, CRSA_BN_CNT)
    BN_DEFINE(pMod, CRSA_BN_CNT)

    if(!src->cnt){
        if(dst != src)
            BN_RST(dst);
        return;
    }

    BN_COPY(pOut, src);
    // uint16_t loop = 0;
    while(bn_cmp_be(pOut, modulus)){
        bn_modulus_align(modulus, pOut, pMod);
        bn_minus(pOut, pMod, pOut);
        // loop++;
    }
    // LOG("mod loop: %d\r\n", loop);
    BN_COPY(dst, pOut);
    FASSERT(dst->maxcnt >= pOut->cnt) //不支持取余溢出
    FASSERT(dst == modulus || bn_cmp_l(dst, modulus))
}
void bn_modexp(const BN_T *src, const BN_T *exp, const BN_T *mod, BN_T *dst){
    FASSERT(src && exp && mod && dst)
    FASSERT(BN_IS_NOT_EMPTY(mod))

    BN_DEFINE(loop, CRSA_CNT_U16)
    BN_DEFINE(src_copy, CRSA_BN_CNT)    //避免dst = src
    BN_DEFINE(ans, CRSA_BN_CNT, 1)

    BN_COPY(loop, exp)
    BN_COPY(src_copy, src)

    if(BN_IS_ZERO(exp)){
        BN_COPY(dst, ans)
        return;
    }else if(BN_IS_ZERO(src)){
        BN_RST(dst)
        return;
    }
    bn_mod(src_copy, mod, src_copy);
    while(loop->cnt){
        if(loop->val[0] & 1){
            bn_mult(ans, src_copy, ans);
            bn_mod(ans, mod, ans);
        }
        bn_mult(src_copy, src_copy, src_copy);
        // BN_PRINT(dst_copy)
        bn_mod(src_copy, mod, src_copy);
        // BN_PRINT(dst_copy)
        bn_devide_num(loop, 2, loop);
        // BN_PRINT(loop)
    }
    BN_COPY(dst, ans)
}

int16_t bn_init(void){
    int16_t ret = 0;
    //参数检查
__exit:
    return ret;
}
