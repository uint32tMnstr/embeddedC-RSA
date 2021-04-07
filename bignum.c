#include <string.h>
#include "crsa_common.h"
#include "bignum.h"

#define BN_CMP(_src, __opt__, _ref)                                                                 \
    {                                                                                               \
        BN_CHECK(_src);                                                                             \
        BN_CHECK(_ref);                                                                             \
        if (_src->cnt && _src->cnt == _ref->cnt)                                                    \
        {                                                                                           \
            BN_CNT_T i = _src->cnt;                                                                 \
            for (; i >= CNT_OF_MAX_UNIT;)                                                           \
            {                                                                                       \
                i -= CNT_OF_MAX_UNIT;                                                               \
                if (VAL_OF_MAX_UNIT(_src->val + i) != VAL_OF_MAX_UNIT(_ref->val + i))               \
                    return (VAL_OF_MAX_UNIT(_src->val + i) __opt__ VAL_OF_MAX_UNIT(_ref->val + i)); \
            }                                                                                       \
            for (; i && _src->val[i] == _ref->val[i]; --i)                                          \
                ;                                                                                   \
            return (_src->val[i] __opt__ _ref->val[i]);                                             \
        }                                                                                           \
        return (_src->cnt __opt__ _ref->cnt);                                                       \
    }
BOOL bn_cmp_e(const BN_T *src, const BN_T *ref) BN_CMP(src, ==, ref)
BOOL bn_cmp_l(const BN_T *src, const BN_T *ref) BN_CMP(src, <, ref)
BOOL bn_cmp_le(const BN_T *src, const BN_T *ref) BN_CMP(src, <=, ref)
BOOL bn_cmp_b(const BN_T *src, const BN_T *ref) BN_CMP(src, >, ref)
BOOL bn_cmp_be(const BN_T *src, const BN_T *ref) BN_CMP(src, >=, ref)

void bn_add_num(const BN_T *src, const opt_num_t num, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(dst && dst->maxcnt > 0)

    maxunit_t tmp = num;
    BN_CNT_T i, maxcnt;
    //TODO: 把num扩展成maxunit_t，对于溢出和大于src的情况，调用bn_add

    maxcnt = MIN(src->maxcnt, dst->maxcnt);
    for (i = 0; tmp && i + CNT_OF_OPT <= maxcnt; i += CNT_OF_OPT)
    {
        tmp += (maxunit_t)VAL_OF_OPT(src->val + i);
        VAL_OF_OPT(dst->val + i) = tmp;
        tmp >>= BITS_OF_OPT;
    }
    for (; tmp && i < maxcnt; ++i)
    {
        tmp += (maxunit_t)src->val[i];
        dst->val[i] = tmp;
        tmp >>= BITS_OF_BN_VAL;
    }

    if (src == dst)
        i = MAX(i, src->cnt);
    else if (tmp)
    {
        for (; i < dst->maxcnt; ++i)
        {
            dst->val[i] = tmp;
            tmp >>= BITS_OF_BN_VAL;
        }
    }
    else
    {
        maxcnt = MIN(src->cnt, dst->maxcnt);
        if (i < maxcnt)
        {
            MEMCPY(&dst->val[i], &src->val[i], sizeof(BN_UNIT_T) * (maxcnt - i));
            i = maxcnt;
        }
    }

    BN_CLEAR(dst, i);
}
void bn_minus_num(const BN_T *src, const opt_num_t num, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(dst && dst->maxcnt > 0)
    //TODO: 扩展num到maxunit_t，对于小于num的src，将src转成maxunit_t，相减后保存到dst
    FASSERT(src->maxcnt * sizeof(BN_UNIT_T) >= sizeof(opt_num_t))

    BN_CNT_T i, maxcnt;
    BOOL brw_flag;

    maxcnt = MIN(src->cnt, dst->maxcnt);
    brw_flag = (VAL_OF_OPT(src->val) < num);
    VAL_OF_OPT(dst->val) = VAL_OF_OPT(src->val) - num;
    for (i = CNT_OF_OPT; brw_flag && i + CNT_OF_MAX_UNIT <= maxcnt; i += CNT_OF_MAX_UNIT)
    {
        if (VAL_OF_MAX_UNIT(src->val + i))
        {
            VAL_OF_MAX_UNIT(dst->val + i) = VAL_OF_MAX_UNIT(src->val + i) - 1;
            brw_flag = 0;
        }
        else
            VAL_OF_MAX_UNIT(dst->val + i) = MAX_VAL_OF_MAX_UNIT;
    }
    for (; brw_flag && i < maxcnt; ++i)
    {
        if (src->val[i])
        {
            dst->val[i] = src->val[i] - 1;
            brw_flag = 0;
        }
        else
            dst->val[i] = MAX_VAL_OF_BN_UNIT;
    }

    if (dst == src)
        maxcnt = MAX(i, maxcnt);
    if (brw_flag)
    { // 下溢
        if (i < dst->maxcnt)
        {
            MEMSET(&dst->val[i], 0xFF, sizeof(BN_UNIT_T) * (dst->maxcnt - i));
            maxcnt = dst->maxcnt;
        }
    }
    else if (i < maxcnt)
    { // 未下溢
        MEMCPY(&dst->val[i], &src->val[i], sizeof(BN_UNIT_T) * (maxcnt - i));
    }
    BN_CLEAR(dst, maxcnt);
    // FASSERT(!brw_flag) //禁止下溢
}
void bn_mult_num(const BN_T *src, const opt_num_t num, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(dst && dst->maxcnt > 0)
    // TODO: 扩展 num 到 maxunit_t

    maxunit_t tmp = 0;
    BN_CNT_T i, maxcnt;

    maxcnt = MIN(src->cnt, dst->maxcnt);
    for (i = 0; i + CNT_OF_OPT <= maxcnt; i += CNT_OF_OPT)
    {
        tmp += (maxunit_t)num * (maxunit_t)VAL_OF_OPT(src->val + i);
        VAL_OF_OPT(dst->val + i) = tmp;
        tmp >>= BITS_OF_OPT;
    }
    for (; i < maxcnt; ++i)
    {
        tmp += (maxunit_t)num * (maxunit_t)src->val[i];
        dst->val[i] = tmp;
        tmp >>= BITS_OF_BN_VAL;
    }
    for (; tmp && i < dst->maxcnt; ++i)
    {
        dst->val[i] = tmp;
        tmp >>= BITS_OF_BN_VAL;
    }

    BN_CLEAR(dst, i);
    // FASSERT(!tmp)    //禁止上溢
}
void bn_devide_num(const BN_T *src, const opt_num_t num, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(dst && dst->maxcnt > 0)
    FASSERT(num)
    // TODO: 扩展 num 到 maxunit_t

    maxunit_t tmp = 0;
    BN_CNT_T i, maxcnt;
    opt_num_t remainder = 0;

    if (BN_EMPTY(src))
    {
        BN_CLEAR(dst, 0);
        return;
    }

    i = src->cnt;
    maxcnt = MIN(src->cnt, dst->maxcnt);
    // src无法复制到dst的部分
    for (; i >= maxcnt + CNT_OF_OPT;)
    {
        i -= CNT_OF_OPT;
        tmp = ((tmp << BITS_OF_OPT) + (maxunit_t)VAL_OF_OPT(src->val + i)) % num;
    }
    for (; i > maxcnt;)
    {
        --i;
        tmp = ((tmp << BITS_OF_BN_VAL) + (maxunit_t)src->val[i]) % num;
    }
    // src可以复制到dst的部分
    for (; i >= CNT_OF_OPT;)
    {
        i -= CNT_OF_OPT;
        tmp = (tmp << BITS_OF_OPT) + (maxunit_t)VAL_OF_OPT(src->val + i);
        VAL_OF_OPT(dst->val + i) = tmp / num;
        tmp %= (maxunit_t)num;  //remainder
    }
    for (; i;)
    {
        --i;
        tmp = (tmp << BITS_OF_BN_VAL) + (maxunit_t)src->val[i];
        dst->val[i] = tmp / num;
        // LOG("%08X %04X\r\n", tmp, dst->val[i]);
        tmp %= (maxunit_t)num;  //remainder
    }
    BN_CLEAR(dst, maxcnt);
}

void bn_add(const BN_T *src1, const BN_T *src2, BN_T *dst)
{
    //NOTE: do not copy src1 or src2 to dst.
    //      consider: if dst == src1 is true, copy src2 to dst.
    BN_CHECK(src1)
    BN_CHECK(src2)
    FASSERT(dst && dst->maxcnt > 0)

    maxunit_t tmp = 0;
    BN_CNT_T i, maxcnt;

    i = 0;
    maxcnt = MIN(MIN(src1->cnt, src2->cnt), dst->maxcnt);
    for (; i + CNT_OF_OPT <= maxcnt; i += CNT_OF_OPT)
    {
        tmp += (maxunit_t)VAL_OF_OPT(src1->val + i) + (maxunit_t)VAL_OF_OPT(src2->val + i);
        VAL_OF_OPT(dst->val + i) = tmp;
        tmp >>= BITS_OF_OPT;
    }
    for (; i < maxcnt; ++i)
    {
        tmp += (maxunit_t)src1->val[i] + (maxunit_t)src2->val[i];
        dst->val[i] = tmp;
        tmp >>= BITS_OF_BN_VAL;
    }
    if (i < dst->maxcnt)
    {
        const BN_T *big_src;
        big_src = (src1->cnt > src2->cnt) ? src1 : src2;
        maxcnt = MIN(big_src->cnt, dst->maxcnt);
        for (; i + CNT_OF_OPT <= maxcnt; i += CNT_OF_OPT)
        {
            tmp += VAL_OF_OPT(big_src->val + i);
            VAL_OF_OPT(dst->val + i) = tmp;
            tmp >>= BITS_OF_OPT;
        }
        for (; i < maxcnt; ++i)
        {
            tmp += (maxunit_t)big_src->val[i];
            dst->val[i] = tmp;
            tmp >>= BITS_OF_BN_VAL;
        }
        FASSERT(!(tmp >> BITS_OF_BN_VAL))
        if (tmp && i < dst->maxcnt)
        {
            dst->val[i] = tmp;
            ++i;
        }
    }
    BN_CLEAR(dst, i);
}
void bn_minus(const BN_T *src1, const BN_T *src2, BN_T *dst)
{
    BN_CHECK(src1)
    BN_CHECK(src2)
    FASSERT(dst && dst->maxcnt > 0)

    BN_CNT_T i, maxcnt;
    BOOL brw_flag = 0, brw_flag_last; //防止((dst == src1)||(dst == src2))为真出现借位问题

    maxcnt = MIN(MIN(src1->cnt, src2->cnt), dst->maxcnt);
    for (i = 0; i + CNT_OF_MAX_UNIT <= maxcnt; i += CNT_OF_MAX_UNIT)
    {
        brw_flag_last = brw_flag;
        brw_flag = (VAL_OF_MAX_UNIT(src1->val + i) < VAL_OF_MAX_UNIT(src2->val + i) + brw_flag_last);
        VAL_OF_MAX_UNIT(dst->val + i) = VAL_OF_MAX_UNIT(src1->val + i) - VAL_OF_MAX_UNIT(src2->val + i) - brw_flag_last;
    }
    for (; i < maxcnt; ++i)
    {
        brw_flag_last = brw_flag;
        brw_flag = (src1->val[i] < src2->val[i] + brw_flag_last);
        dst->val[i] = src1->val[i] - src2->val[i] - brw_flag_last;
    }
    if (i < dst->maxcnt)
    {
        if (src1->cnt > src2->cnt)
        {
            maxcnt = MIN(src1->cnt, dst->maxcnt);
            for (; brw_flag && i + CNT_OF_MAX_UNIT <= maxcnt; i += CNT_OF_MAX_UNIT)
            {
                if (VAL_OF_MAX_UNIT(src1->val + i))
                {
                    VAL_OF_MAX_UNIT(dst->val + i) = VAL_OF_MAX_UNIT(src1->val + i) - 1;
                    brw_flag = 0;
                }
                else
                    VAL_OF_MAX_UNIT(dst->val + i) = MAX_VAL_OF_MAX_UNIT;
            }
            for (; brw_flag && i < maxcnt; ++i)
            {
                if (src1->val[i])
                {
                    dst->val[i] = src1->val[i] - 1;
                    brw_flag = 0;
                }
                else
                    dst->val[i] = MAX_VAL_OF_BN_UNIT;
            }
            FASSERT(!brw_flag)
            if (dst == src1)
                i = MAX(i, maxcnt);
            else if (i < maxcnt)
            {
                MEMCPY(&dst->val[i], &src1->val[i], sizeof(BN_UNIT_T) * (maxcnt - i));
                i = maxcnt;
            }
        }
        else if (src1->cnt < src2->cnt)
        {
            maxcnt = MIN(src2->cnt, dst->maxcnt);
            for (; i + CNT_OF_MAX_UNIT <= maxcnt; i += CNT_OF_MAX_UNIT)
                VAL_OF_MAX_UNIT(dst->val + i) = MAX_VAL_OF_MAX_UNIT - VAL_OF_MAX_UNIT(src2->val + i);
            for (; i < maxcnt; ++i)
                dst->val[i] = MAX_VAL_OF_BN_UNIT - src2->val[i];
            if (i < dst->maxcnt)
            {
                MEMSET(&dst->val[i], 0xFF, sizeof(BN_UNIT_T) * (dst->maxcnt - i));
                i = dst->maxcnt;
            }
        }
    }
    BN_CLEAR(dst, i)
}

static void bn_mult_base_fft(const uint16_t *poly, const uint16_t coe, uint16_t *output)
{ //O(nlogn)
    //TODO:
}
static void bn_mult_base_normal(const BN_T *src1, const BN_T *src2, BN_T *dst)
{ //O(n^2)
    BN_CHECK(src1)
    BN_CHECK(src2)
    FASSERT(dst && dst->maxcnt > 0)

    maxunit_t tmp;
    BN_CNT_T i, j = 0 /* 必须初始化，避免src2的值为0 */;
    BASE_BN_DEFINE(pOut, CNT_OF_BN_VAL * 2)

    if (bn_cmp_l(src1, src2))
    {
        const BN_T *exchg = src1;
        src1 = src2;
        src2 = exchg;
    }
    FASSERT(src1->cnt + src2->cnt - (!(((maxunit_t)src1->val[src1->cnt - 1] * (maxunit_t)src2->val[src2->cnt - 1]) >> 16)) <= pOut->maxcnt)

    for (i = 0; i + CNT_OF_OPT <= src2->cnt; i += CNT_OF_OPT)
    {
        tmp = 0;
        for (j = 0; j + CNT_OF_OPT <= src1->cnt; j += CNT_OF_OPT)
        {
            tmp = tmp + (maxunit_t)VAL_OF_OPT(src2->val + i) * (maxunit_t)VAL_OF_OPT(src1->val + j) + (maxunit_t)VAL_OF_OPT(pOut->val + i + j);
            VAL_OF_OPT(pOut->val + i + j) = tmp;
            tmp >>= BITS_OF_OPT;
        }
        for (; j < src1->cnt; ++j)
        {
            tmp = tmp + (maxunit_t)VAL_OF_OPT(src2->val + i) * (maxunit_t)src1->val[j] + (maxunit_t)pOut->val[i + j];
            pOut->val[i + j] = tmp;
            tmp >>= BITS_OF_BN_VAL;
        }
        VAL_OF_OPT(pOut->val + i + j) = tmp;
        j += CNT_OF_OPT;
    }
    for (; i < src2->cnt; ++i)
    {
        tmp = 0;
        for (j = 0; j + CNT_OF_OPT <= src1->cnt; j += CNT_OF_OPT)
        {
            tmp = tmp + (maxunit_t)src2->val[i] * (maxunit_t)VAL_OF_OPT(src1->val + j) + (maxunit_t)VAL_OF_OPT(pOut->val + i + j);
            VAL_OF_OPT(pOut->val + i + j) = tmp;
            tmp >>= BITS_OF_OPT;
        }
        for (; j < src1->cnt; ++j)
        {
            tmp = tmp + (maxunit_t)src2->val[i] * (maxunit_t)src1->val[j] + (maxunit_t)pOut->val[i + j];
            pOut->val[i + j] = tmp;
            tmp >>= BITS_OF_BN_VAL;
        }
        pOut->val[i + j] = tmp;
        ++j;
    }
    BN_CLEAR(pOut, i + j)
    BN_COPY(dst, pOut);
}
void bn_mult(const BN_T *src1, const BN_T *src2, BN_T *dst)
{
    bn_mult_base_normal(src1, src2, dst);
}

uint16_t bn_bits(const BN_T *pbn)
{
    BN_CHECK(pbn)

    BN_UNIT_T val;
    uint16_t shift_bits = 0;

    if (BN_NOT_EMPTY(pbn))
    {
        val = pbn->val[pbn->cnt - 1];
        shift_bits = (pbn->cnt - 1) * BITS_OF_BN_VAL;
#if 0 //def __OPT_64
            if(val & ((maxunit_t)0xFFFFFFFF00000000))
            {
                shift_bits += 32;
                val >>= 32;
            }
#endif
        if (val & 0xFFFF0000)
        {
            shift_bits += 16;
            val >>= 16;
        }
        if (val & 0xFF00)
        {
            shift_bits += 8;
            val >>= 8;
        }
        if (val & 0xF0)
        {
            shift_bits += 4;
            val >>= 4;
        }
        shift_bits +=   (val & 8)?4: \
                        (val & 4)?3: \
                        (val & 2)?2:
                        (val & 1);
    }

    return shift_bits;
}

void bn_shift_l(const BN_T *src, uint16_t shift_bits, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(dst && dst->maxcnt > 0)

    uint16_t shift_cnt, i, maxcnt;
    BASE_BN_DEFINE(pOut, CNT_OF_BN_VAL * 2) //防止dst == src

    shift_cnt = shift_bits / BITS_OF_BN_VAL;
    shift_bits %= BITS_OF_BN_VAL;
    maxcnt = MIN(src->cnt, MAX(dst->maxcnt, shift_cnt) - shift_cnt);

    if (shift_bits)
    {
        maxunit_t tmp = 0;
        for (i = 0; i + CNT_OF_OPT <= maxcnt; i += CNT_OF_OPT)
        {
            tmp |= (((maxunit_t)VAL_OF_OPT(src->val + i)) << shift_bits);
            VAL_OF_OPT(pOut->val + i + shift_cnt) = tmp;
            tmp >>= BITS_OF_OPT;
        }
        for (; i < maxcnt; ++i)
        {
            tmp |= (((uint32_t)src->val[i]) << shift_bits);
            pOut->val[i + shift_cnt] = tmp;
            tmp >>= BITS_OF_BN_VAL;
        }
        i += shift_cnt;
        FASSERT(!(tmp >> BITS_OF_BN_VAL))
        if (tmp && i < dst->maxcnt)
        {
            pOut->val[i] = tmp;
            ++i;
        }
    }
    else
    {
        // MEMSET(pOut->val, 0, sizeof(uint16_t) * shift_cnt);
        MEMCPY(&pOut->val[shift_cnt], src->val, sizeof(BN_UNIT_T) * maxcnt);
        i = shift_cnt + maxcnt;
    }
    BN_CLEAR(pOut, i);
    BN_COPY(dst, pOut);
}
void bn_mod_align(const BN_T *src, const BN_T *ref, BN_T *dst)
{
    BN_CHECK(src)
    BN_CHECK(ref)
    FASSERT(BN_NOT_EMPTY(src))
    FASSERT(BN_NOT_EMPTY(ref))
    FASSERT(dst && dst->maxcnt >= ref->cnt)

    uint16_t shift_bits;

    if (bn_cmp_be(src, ref))
    {
        BN_COPY(dst, src)
        return;
    }
    shift_bits = bn_bits(ref) - bn_bits(src);
    if(shift_bits < 2)
    {
        BN_COPY(dst, src)
        return;
    }

    bn_shift_l(src, shift_bits - 1, dst);
}

void bn_mod(const BN_T *src, const BN_T *mod, BN_T *dst)
{
    BN_CHECK(src)
    FASSERT(BN_NOT_EMPTY(mod))
    FASSERT(dst)
    LOGBN("%s(%d) - entry\r\n", __FUNCTION__, __LINE__);

    BASE_BN_DEFINE(pOut, CNT_OF_BN_VAL * 2)
    BASE_BN_DEFINE(pModAlign, CNT_OF_BN_VAL * 2)

    if (!src->cnt)
    {
        if (dst != src)
            BN_RST(dst);
        return;
    }

    BN_COPY(pOut, src);
    while (bn_cmp_be(pOut, mod))
    {
        bn_mod_align(mod, pOut, pModAlign);
        bn_minus(pOut, pModAlign, pOut);
    }
    BN_COPY(dst, pOut);
    FASSERT(dst->maxcnt >= pOut->cnt) //不支持取余溢出
    FASSERT(dst == mod || bn_cmp_l(dst, mod))
    LOGBN("%s(%d) - exit\r\n", __FUNCTION__, __LINE__);
}
void bn_modexp(const BN_T *src, const BN_T *exp, const BN_T *mod, BN_T *dst)
{
    FASSERT(src && exp && mod && dst)
    FASSERT(BN_NOT_EMPTY(mod))
    LOGBN("%s(%d) - entry\r\n", __FUNCTION__, __LINE__);

    BASE_BN_DEFINE(loop, CNT_OF_BN_VAL)
    BASE_BN_DEFINE(src_copy, CNT_OF_BN_VAL * 2) //避免dst = src
    BN_DEFINE(ans, CNT_OF_BN_VAL * 2, 1)

    BN_COPY(loop, exp)
    BN_COPY(src_copy, src)

    if (BN_EMPTY(exp))
    {
        BN_COPY(dst, ans)
        return;
    }
    else if (BN_EMPTY(src))
    {
        BN_RST(dst)
        return;
    }
    bn_mod(src_copy, mod, src_copy);
    while (loop->cnt)
    {
        if (loop->val[0] & 1)
        {
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
    LOGBN("%s(%d) - exit\r\n", __FUNCTION__, __LINE__);
}

int16_t bn_init(void)
{
    int16_t ret = 0;
    //参数检查
    UASSERT(!((CRSA_KEY_BITS / BITS_OF_BYTE) % sizeof(BN_UNIT_T)), ret = CRSA_EC_KEY_BITS);
    UASSERT(sizeof(maxunit_t) > sizeof(opt_num_t), ret = CRSA_EC_OPT_BITS);
    UASSERT(sizeof(opt_num_t) >= sizeof(BN_UNIT_T), ret = CRSA_EC_BN_UNIT);
__exit:
    return ret;
}