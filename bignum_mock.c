#include <stdlib.h>
#include "crsa_common.h"
#include "bignum.h"

#define BASE_FILL_RANDOM_BN_VAL(_bn, _cnt)                          \
    {                                                         \
        for (uint32_t _idx = 0; _idx < _cnt; ++_idx) \
            _bn->val[_idx] = rand();                          \
        BN_SET_CNT(_bn)                                       \
    }
#define FILL_RANDOM_BN_VAL(_bn, _cnt) BASE_FILL_RANDOM_BN_VAL(BN_PTR(_bn), BN_CNT(_cnt))
#define MOCK_ASSERT(con, _num, ...)                              \
    {                                                            \
        if (!(con))                                              \
        {                                                        \
            BN_T *_bnarray[] = {0, __VA_ARGS__};                 \
            uint16_t _count = sizeof(_bnarray) / sizeof(BN_T *); \
            LOG("[FATAL] %s(%d)\r\n", __FUNCTION__, __LINE__);   \
            LOG("num: 0x%X\r\n", _num);                          \
            for (uint16_t _i = 1; _i < _count; ++_i)             \
                BN_PRINT(_bnarray[_i]);                          \
            while (1)                                            \
                ;                                                \
        }                                                        \
    }
void bn_num_mock()
{

    FASSERT(BITS_OF_BN_VAL == 16)

    opt_num_t tmp;
    BN_DEFINE(bnsrc, CNT_OF_BN_VAL)
    BN_DEFINE(bnret, CNT_OF_BN_VAL)
    BN_DEFINE(bnret2, CNT_OF_BN_VAL + 1)

    // BN_DEFINE(bnerr, CNT_OF_BN_VAL,
    //     0x4823, 0x18BE, 0x6784, 0x4AE1, 0x3D6C, 0x2CD6, 0x72AE, 0x6952,
    //     0x5F90, 0x1649, 0x6DF1, 0x5AF1, 0x41BB, 0x26E9, 0x01EB, 0x0BB3)
    // tmp = 0x29;
    // BN_PRINT(bnerr);
    // BN_COPY(bnret, bnerr);
    // bn_add_num(bnret, tmp, bnret);
    // BN_PRINT(bnret);
    // bn_minus_num(bnret, tmp, bnret);
    // BN_PRINT(bnret);
    // FASSERT(bn_cmp_e(bnret, bnerr))
    // bn_mult_num(bnerr, tmp, bnret2);
    // BN_PRINT(bnret2)
    // bn_devide_num(bnret2, tmp, bnret2);
    // BN_PRINT(bnret2)
    // FASSERT(bn_cmp_e(bnret2, bnerr))
    srand(2153);
    for (uint32_t i = 0; i < 0xFFFFF; ++i)
    {
        tmp = rand();
        // tmp = rand() | 0x8000;
        // 生成随机大数
        FILL_RANDOM_BN_VAL(bnsrc, CNT_OF_BN_VAL);
        bn_add_num(bnsrc, tmp, bnret);
        MOCK_ASSERT(!tmp || !bn_cmp_e(bnret, bnsrc), tmp, bnsrc, bnret);
        bn_minus_num(bnret, tmp, bnret);
        MOCK_ASSERT(bn_cmp_e(bnret, bnsrc), tmp, bnsrc, bnret);

        bn_add_num(bnret, tmp, bnret);
        MOCK_ASSERT(!tmp || !bn_cmp_e(bnret, bnsrc), tmp, bnsrc, bnret);
        bn_minus_num(bnret, tmp, bnret);
        MOCK_ASSERT(bn_cmp_e(bnret, bnsrc), tmp, bnsrc, bnret);

        tmp |= 1;
        bn_mult_num(bnsrc, tmp, bnret2);
        bn_devide_num(bnret2, tmp, bnret);
        MOCK_ASSERT(bn_cmp_e(bnret, bnsrc), tmp, bnsrc, bnret);
        BN_COPY(bnret2, bnsrc);
        bn_mult_num(bnret2, tmp, bnret2);
        bn_devide_num(bnret2, tmp, bnret2);
        MOCK_ASSERT(bn_cmp_e(bnret2, bnsrc), tmp, bnsrc, bnret2);
    }

    // BN_DEFINE(bnadd, CNT_OF_BN_VAL,
    //           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    //           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    // BN_DEFINE(bn2, CNT_OF_BN_VAL)
    // BN_DEFINE(bn3, CNT_OF_BN_VAL + 1)
    // BN_DEFINE(bn4, CNT_OF_BN_VAL / 2)
    // bn_add_num(bnadd, 1, bn2);
    // BN_PRINT(bn2)
    // bn_add_num(bnadd, 2, bn2);
    // BN_PRINT(bn2)
    // bn_add_num(bnadd, 0xFFFF, bn2);
    // BN_PRINT(bn2)
    // bn_add_num(bnadd, 1, bn3);
    // BN_PRINT(bn3)
    // bn_add_num(bnadd, 2, bn3);
    // BN_PRINT(bn3)
    // bn_add_num(bnadd, 0xFFFF, bn3);
    // BN_PRINT(bn3)
    // bn_add_num(bnadd, 0, bn4);
    // BN_PRINT(bn4)
    // bn_add_num(bnadd, 1, bn4);
    // BN_PRINT(bn4)
    // LOG("\r\n");

    // BN_DEFINE(bnminus, CNT_OF_BN_VAL, 1, 1)
    // // BN_DEFINE(bnminus, CNT_OF_BN_VAL, 1)
    // bn_minus_num(bnminus, 1, bn2);
    // BN_PRINT(bn2)
    // bn_minus_num(bnminus, 2, bn2);
    // BN_PRINT(bn2)
    // bn_minus_num(bnminus, 0, bn2);
    // BN_PRINT(bn2)
    // bn_minus_num(bnminus, 1, bn3);
    // BN_PRINT(bn3)
    // bn_minus_num(bnminus, 2, bn3);
    // BN_PRINT(bn3)
    // bn_minus_num(bnminus, 0, bn3);
    // BN_PRINT(bn3)
    // bn_minus_num(bnminus, 2, bn4);
    // BN_PRINT(bn4)
    // LOG("\r\n");

    // BN_DEFINE(bnmult, CNT_OF_BN_VAL, )
    // BN_T *bnmult = bnadd;
    // bn_mult_num(bnmult, 1, bn2);
    // BN_PRINT(bn2)
    // bn_mult_num(bnmult, 2, bn2);
    // BN_PRINT(bn2)
    // bn_mult_num(bnmult, 0, bn2);
    // BN_PRINT(bn2)
    // bn_mult_num(bnmult, 1, bn3);
    // BN_PRINT(bn3)
    // bn_mult_num(bnmult, 2, bn3);
    // BN_PRINT(bn3)
    // bn_mult_num(bnmult, 0, bn3);
    // BN_PRINT(bn3)
    // bn_mult_num(bnmult, 2, bn4);
    // BN_PRINT(bn4)
    // LOG("\r\n");
    // // BN_DEFINE(bnmult, CNT_OF_BN_VAL, )
    // BN_T *bndvd = bnadd;
    // bn_devide_num(bndvd, 1, bn2);
    // BN_PRINT(bn2)
    // bn_devide_num(bndvd, 2, bn2);
    // BN_PRINT(bn2)
    // bn_devide_num(bndvd, 0xFFFF, bn2);
    // BN_PRINT(bn2)
    // bn_devide_num(bndvd, 1, bn3);
    // BN_PRINT(bn3)
    // bn_devide_num(bndvd, 2, bn3);
    // BN_PRINT(bn3)
    // bn_devide_num(bndvd, 0xFFFF, bn3);
    // BN_PRINT(bn3)
    // bn_devide_num(bndvd, 2, bn4);
    // BN_PRINT(bn4)
    // bn_devide_num(bnminus, 2, bn4);
    // BN_PRINT(bn4)
    LOG("%s(%d) SUCCESSFUL !!!\r\n", __FUNCTION__, __LINE__);
}
void bn_minus_mock()
{
    BN_DEFINE(bn1, CNT_OF_BN_VAL,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    BN_DEFINE(bn2, CNT_OF_BN_VAL,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE);
    BN_DEFINE(bn3, CNT_OF_BN_VAL,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 2, 0);
    BN_DEFINE(bnret, CNT_OF_BN_VAL)

    FASSERT(CNT_OF_BN_VAL == 16)
    bn_minus(bn1, bn2, bnret);
    BN_PRINT(bnret);
    bn_minus(bn2, bn1, bnret);
    BN_PRINT(bnret);
    bn_minus(bn1, bn1, bnret);
    BN_PRINT(bnret);
    bn_minus(bn2, bn3, bn2);
    BN_PRINT(bn2);
    bn1->val[CNT_OF_BN_VAL - 1] = 0;
    bn1->val[CNT_OF_BN_VAL - 2] = 1;
    BN_CLEAR(bn1, CNT_OF_BN_VAL);
    BN_PRINT(bn1);
    bn_minus(bn1, bn3, bn1);
    BN_PRINT(bn1);
    bn_minus(bn3, bnret, bn3);
    BN_PRINT(bn3);
}
void bn_add_mock()
{
    BN_DEFINE(bn1, CNT_OF_BN_VAL,
              0xFFFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    BN_DEFINE(bn2, CNT_OF_BN_VAL,
              1, 0xFFFF - 2 + 1, 0xFFFF - 3 + 1, 0xFFFF - 4 + 1,
              0xFFFF - 5 + 1, 0xFFFF - 6 + 1, 0xFFFF - 7 + 1, 0xFFFF - 8 + 1,
              0xFFFF - 9 + 1, 0xFFFF - 10 + 1, 0xFFFF - 11 + 1, 0xFFFF - 12 + 1,
              0xFFFF - 13 + 1, 0xFFFF - 14 + 1, 0xFFFF - 15 + 1, 0xFFFF - 16 + 1);
    BN_DEFINE(bn3, CNT_OF_BN_VAL, 1);
    BN_DEFINE(bnret, CNT_OF_BN_VAL + 1);

    FASSERT(CNT_OF_BN_VAL == 16)
    bn_add(bn1, bn3, bnret);
    BN_PRINT(bnret);
    bn_add(bn1, bn2, bnret);
    BN_PRINT(bnret);
    bn_add(bn1, bn2, bn1);
    BN_PRINT(bn1);
    bn_add(bn1, bn1, bn1);
    BN_PRINT(bn1);
    bn_add(bn1, bn3, bn1);
    BN_PRINT(bn1);
    bn_add(bn3, bn1, bn1);
    BN_PRINT(bn1);
}
void bn_define_mock()
{
    FASSERT(CNT_OF_BN_VAL == 16)
    BN_DEFINE(bn1, CNT_OF_BN_VAL,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CNT_OF_BN_VAL,
              0xFFFF, 0, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn3, CNT_OF_BN_VAL + 1, 1, 2, 0, 0, 1, 0)
    // LOG_SHORT("bn3", bn3->val, CNT_OF_BN_VAL);
    BN_DEFINE(bn4, CNT_OF_BN_VAL)
    // LOG_SHORT("bn4", bn4->val, CNT_OF_BN_VAL);
    BN_PRINT(bn1)
    BN_PRINT(bn2)
    BN_PRINT(bn3)
    BN_PRINT(bn4)
}
void bn_mult_mock()
{
    FASSERT(CNT_OF_BN_VAL == 16)
    int16_t ret = bn_init();
    BN_DEFINE(bn1, CNT_OF_BN_VAL,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CNT_OF_BN_VAL,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn3, CNT_OF_BN_VAL + 1,
              0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 2)
    BN_DEFINE(bn4, CNT_OF_BN_VAL, 1)
    BN_DEFINE(bn5, CNT_OF_BN_VAL)
    BN_DEFINE(bnret, CNT_OF_BN_VAL* 2)

    bn_mult(bn1, bn2, bn2);   BN_PRINT(bn2);
    bn_mult(bn1, bn1, bnret); BN_PRINT(bnret);
    bn_mult(bn1, bn3, bn3); BN_PRINT(bn3);
    bn_mult(bn1, bn4, bnret); BN_PRINT(bnret);
    bn_mult(bn4, bn1, bnret); BN_PRINT(bnret);
    bn_mult(bn1, bn5, bnret); BN_PRINT(bnret);
    bn_mult(bn5, bn1, bnret); BN_PRINT(bnret);
    // bn_mult(bn1, bn3, bnret); BN_PRINT(bnret);  //FATAL: 计算溢出
}
void bn_cmp_mock()
{
    BN_DEFINE(bn1, CNT_OF_BN_VAL,
              1);
    BN_DEFINE(bn2, 5,
              0, 0, 0, 0, 0xFFFF);
    BN_DEFINE(bn3, CNT_OF_BN_VAL,
              0, 0, 0, 0, 0, 1);
    BN_DEFINE(bn4, 6,
              0, 0, 0, 0, 0, 1);

    // BN_PRINT(bn1)
    // BN_PRINT(bn2)
    // BN_PRINT(bn3)
    // BN_PRINT(bn4)

    FASSERT(!bn_cmp_e(bn1, bn2))
    FASSERT(bn_cmp_e(bn2, bn2))
    FASSERT(bn_cmp_e(bn3, bn4))
    FASSERT(bn_cmp_e(bn4, bn3))

    FASSERT(bn_cmp_l(bn1, bn2))
    FASSERT(!bn_cmp_l(bn2, bn1))
    FASSERT(!bn_cmp_l(bn2, bn2))
    FASSERT(!bn_cmp_l(bn3, bn4))

    FASSERT(bn_cmp_le(bn1, bn2))
    FASSERT(!bn_cmp_le(bn2, bn1))
    FASSERT(bn_cmp_le(bn3, bn4))
    FASSERT(bn_cmp_le(bn4, bn3))

    FASSERT(!bn_cmp_b(bn1, bn2))
    FASSERT(bn_cmp_b(bn2, bn1))
    FASSERT(!bn_cmp_b(bn2, bn2))
    FASSERT(!bn_cmp_b(bn3, bn4))

    FASSERT(!bn_cmp_be(bn1, bn2))
    FASSERT(bn_cmp_be(bn2, bn1))
    FASSERT(bn_cmp_be(bn2, bn2))
    FASSERT(bn_cmp_be(bn3, bn4))

    LOG("%s(%d): SUCCESSFUL !!!\r\n", __FUNCTION__, __LINE__);
}
void bn_mod_mock()
{
    BN_DEFINE(bnmod, CNT_OF_BN_VAL * 2)
    BN_DEFINE(bnadder, CNT_OF_BN_VAL)
    BN_DEFINE(bnret, CNT_OF_BN_VAL * 2)
    
    srand(13587);
    FILL_RANDOM_BN_VAL(bnmod, CNT_OF_BN_VAL)
    FILL_RANDOM_BN_VAL(bnadder, CNT_OF_BN_VAL - 1)

    for (uint32_t i = 0; i < 0xFFFFF; ++i)
    {
        uint16_t tmp = rand();
        // BN_PRINT(bnmod)
        tmp = !tmp ? (rand() | 1) : tmp;
        bn_mult_num(bnmod, tmp, bnret);
        // BN_PRINT(bnret)
        //bn_devide_num(bnret, tmp, bnret);
        //MOCK_ASSERT(bn_cmp_e(bnret, bnmod), tmp, bnmod, bnret)
        bn_add(bnret, bnadder, bnret);
        // BN_PRINT(bnret)
        // LOG("cnt = %d of %d\r\n", bnret->cnt, bnret->maxcnt);
        bn_mod(bnret, bnmod, bnret);
        // BN_PRINT(bnret)
        MOCK_ASSERT(bn_cmp_e(bnret, bnadder), tmp, bnmod, bnadder, bnret)
        if(!(i % 0xFFFF))
            LOG("test %d\r\n", i / 0xFFFF);
    }

    // BN_DEFINE(bn1, CNT_OF_BN_VAL,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //         //   0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //         //   0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //         //   0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //         //   0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF)
    // //   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    // //   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    // BN_DEFINE(bn2, CNT_OF_BN_VAL,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF,
    //           0x1234, 0x5678, 0x9ABC, 0xFFFF)
    // BN_DEFINE(bnret, CNT_OF_BN_VAL)

    // BN_PRINT(bn1)
    // BN_PRINT(bn2)
    // BN_PRINT(bnret)

    // bn_shift_l(bn1, 2, bnret);BN_PRINT(bnret);

    // bn_mod(bn1, bn2, bnret);BN_PRINT(bnret);
    // bn_mod(bn2, bn1, bnret);BN_PRINT(bnret);
    // bn_mod(bn1, bn1, bnret);BN_PRINT(bnret);
    // bn1->val[0]--;
    // bn_mod(bn1, bn2, bnret);BN_PRINT(bnret);
    // bn1->val[0] += 2;
    // bn_mod(bn1, bn2, bnret);BN_PRINT(bnret);
    // bn_mod(bn1, bn2, bn2);BN_PRINT(bn2);
    // bn_mod(bn1, bn1, bn2);BN_PRINT(bn2);
    // bn_mod(bn1, bn1, bn1);BN_PRINT(bn1);
    // bn_mod(bn1, bnret, bn1);BN_PRINT(bn1);
    // bn_mod(bn1, bn2, bn1); BN_PRINT(bn1);    //FATAL: modulus = 0
}
void bn_opt_mock()
{
    BN_DEFINE(bnsrc1, CNT_OF_BN_VAL);
    BN_DEFINE(bnsrc2, CNT_OF_BN_VAL);
    BN_DEFINE(bnret1, CNT_OF_BN_VAL);
    BN_DEFINE(bnret11, CNT_OF_BN_VAL);

    srand(656);
    for(uint32_t i = 0; i < 0xFFFFFF; ++i)
    {
        FILL_RANDOM_BN_VAL(bnsrc1,CNT_OF_BN_VAL);
        FILL_RANDOM_BN_VAL(bnsrc2,CNT_OF_BN_VAL);
        // BN_PRINT(bnsrc1)BN_PRINT(bnsrc2)
        bn_add(bnsrc1, bnsrc2, bnret1);
        bn_minus(bnret1, bnsrc2, bnret11);
        MOCK_ASSERT(bn_cmp_e(bnret11, bnsrc1), bnsrc1, bnsrc2, bnret1, bnret11);
        BN_COPY(bnret1, bnsrc1);
        bn_add(bnret1, bnsrc2, bnret1);
        bn_minus(bnret1, bnsrc2, bnret1);
        MOCK_ASSERT(bn_cmp_e(bnret1, bnsrc1), bnsrc1, bnsrc2, bnret1);
    }
    LOG("%s(%d) SUCCESSFUL !!!\r\n", __FUNCTION__, __LINE__);
}
#if 0
int main()
{
    // bn_define_mock();
    // bn_cmp_mock();
    // bn_num_mock();
    // bn_opt_mock();
    // bn_minus_mock();
    // bn_add_mock();
    // bn_mult_mock();
    bn_mod_mock();
    return 0;
}
#endif
