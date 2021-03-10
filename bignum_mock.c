#include "crsa_common.h"
#include "bignum.h"

void bn_num_mock(){
    BN_DEFINE(bnadd, CRSA_CNT_U16, 
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CRSA_CNT_U16)
    BN_DEFINE(bn3, CRSA_CNT_U16 + 1)
    BN_DEFINE(bn4, CRSA_CNT_U16 / 2)
    bn_add_num(bnadd, 1, bn2); BN_PRINT(bn2)
    bn_add_num(bnadd, 2, bn2); BN_PRINT(bn2)
    bn_add_num(bnadd, 0xFFFF, bn2); BN_PRINT(bn2)
    bn_add_num(bnadd, 1, bn3); BN_PRINT(bn3)
    bn_add_num(bnadd, 2, bn3); BN_PRINT(bn3)
    bn_add_num(bnadd, 0xFFFF, bn3); BN_PRINT(bn3)
    bn_add_num(bnadd, 0, bn4); BN_PRINT(bn4)
    LOG("\r\n");

    // BN_DEFINE(bnminus, CRSA_CNT_U16, 1, 1)
    BN_DEFINE(bnminus, CRSA_CNT_U16, 1)
    bn_minus_num(bnminus, 1, bn2); BN_PRINT(bn2)
    bn_minus_num(bnminus, 2, bn2); BN_PRINT(bn2)
    bn_minus_num(bnminus, 0, bn2); BN_PRINT(bn2)
    bn_minus_num(bnminus, 1, bn3); BN_PRINT(bn3)
    bn_minus_num(bnminus, 2, bn3); BN_PRINT(bn3)
    bn_minus_num(bnminus, 0, bn3); BN_PRINT(bn3)
    bn_minus_num(bnminus, 2, bn4); BN_PRINT(bn4)
    LOG("\r\n");

    // BN_DEFINE(bnmult, CRSA_CNT_U16, )
    BN_T *bnmult = bnadd;
    bn_mult_num(bnmult, 1, bn2); BN_PRINT(bn2)
    bn_mult_num(bnmult, 2, bn2); BN_PRINT(bn2)
    bn_mult_num(bnmult, 0, bn2); BN_PRINT(bn2)
    bn_mult_num(bnmult, 1, bn3); BN_PRINT(bn3)
    bn_mult_num(bnmult, 2, bn3); BN_PRINT(bn3)
    bn_mult_num(bnmult, 0, bn3); BN_PRINT(bn3)
    bn_mult_num(bnmult, 2, bn4); BN_PRINT(bn4)
    LOG("\r\n");
    // BN_DEFINE(bnmult, CRSA_CNT_U16, )
    BN_T *bndvd = bnadd;
    bn_devide_num(bndvd, 1, bn2); BN_PRINT(bn2)
    bn_devide_num(bndvd, 2, bn2); BN_PRINT(bn2)
    bn_devide_num(bndvd, 0xFFFF, bn2); BN_PRINT(bn2)
    bn_devide_num(bndvd, 1, bn3); BN_PRINT(bn3)
    bn_devide_num(bndvd, 2, bn3); BN_PRINT(bn3)
    bn_devide_num(bndvd, 0xFFFF, bn3); BN_PRINT(bn3)
    bn_devide_num(bndvd, 2, bn4); BN_PRINT(bn4)
    bn_devide_num(bnminus, 2, bn4); BN_PRINT(bn4)
    LOG("\r\n");
}
void bn_minus_mock()
{
    BN_DEFINE(bn1, CRSA_CNT_U16,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    BN_DEFINE(bn2, CRSA_CNT_U16,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE);
    BN_DEFINE(bn3, CRSA_CNT_U16,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 0xEEEE, 0xEEEE,
              0xEEEE, 0xEEEE, 2, 0);
    BN_DEFINE(bnret, CRSA_CNT_U16)

    FASSERT(CRSA_CNT_U16 == 16)
    bn_minus(bn1, bn2, bnret);
    BN_PRINT(bnret);
    bn_minus(bn2, bn1, bnret);
    BN_PRINT(bnret);
    bn_minus(bn1, bn1, bnret);
    BN_PRINT(bnret);
    bn_minus(bn2, bn3, bn2);
    BN_PRINT(bn2);
    bn1->val[CRSA_CNT_U16 - 1] = 0;
    bn1->val[CRSA_CNT_U16 - 2] = 1;
    BN_FMT(bn1, CRSA_CNT_U16);
    BN_PRINT(bn1);
    bn_minus(bn1, bn3, bn1);
    BN_PRINT(bn1);
    bn_minus(bn3, bnret, bn3);
    BN_PRINT(bn3);
}
void bn_add_mock()
{
    BN_DEFINE(bn1, CRSA_CNT_U16,
              0xFFFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    BN_DEFINE(bn2, CRSA_CNT_U16,
              1, 0xFFFF - 2 + 1, 0xFFFF - 3 + 1, 0xFFFF - 4 + 1,
              0xFFFF - 5 + 1, 0xFFFF - 6 + 1, 0xFFFF - 7 + 1, 0xFFFF - 8 + 1,
              0xFFFF - 9 + 1, 0xFFFF - 10 + 1, 0xFFFF - 11 + 1, 0xFFFF - 12 + 1,
              0xFFFF - 13 + 1, 0xFFFF - 14 + 1, 0xFFFF - 15 + 1, 0xFFFF - 16 + 1);
    BN_DEFINE(bn3, CRSA_CNT_U16, 1);
    BN_DEFINE(bnret, CRSA_CNT_U16 + 1);

    FASSERT(CRSA_CNT_U16 == 16)
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
    BN_DEFINE(bn1, CRSA_CNT_U16,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CRSA_CNT_U16,
              0xFFFF, 0, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn3, CRSA_CNT_U16 + 1, 1, 2, 0, 0, 1, 0)
    // LOG_SHORT("bn3", bn3->val, CRSA_CNT_U16);
    BN_DEFINE(bn4, CRSA_CNT_U16)
    // LOG_SHORT("bn4", bn4->val, CRSA_CNT_U16);
    BN_PRINT(bn1)
    BN_PRINT(bn2)
    BN_PRINT(bn3)
    BN_PRINT(bn4)
}
void bn_mult_mock()
{
    int16_t ret = bn_init();
    BN_DEFINE(bn1, CRSA_CNT_U16,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CRSA_CNT_U16,
              0xFFFF, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
              0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn3, CRSA_CNT_U16 + 1,
              0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0,
              2)
    BN_DEFINE(bn4, CRSA_CNT_U16, 1)
    BN_DEFINE(bn5, CRSA_CNT_U16)
    BN_DEFINE(bnret, CRSA_BN_CNT)

    FASSERT(CRSA_CNT_U16 == 16)

    bn_mult(bn1, bn2, bnret);
    BN_PRINT(bnret);
    bn_mult(bn1, bn1, bnret);
    BN_PRINT(bnret);
    bn_mult(bn1, bn4, bnret);
    BN_PRINT(bnret);
    bn_mult(bn4, bn1, bnret);
    BN_PRINT(bnret);
    bn_mult(bn1, bn5, bnret);
    BN_PRINT(bnret);
    bn_mult(bn5, bn1, bnret);
    BN_PRINT(bnret);
    // bn_mult(bn1, bn3, bnret); BN_PRINT(bnret);  //FATAL: 计算溢出
}
void bn_cmp_mock()
{
    BN_DEFINE(bn1, CRSA_CNT_U16,
              1);
    BN_DEFINE(bn2, 5,
              0, 0, 0, 0, 0xFFFF);
    BN_DEFINE(bn3, CRSA_CNT_U16,
              0, 0, 0, 0, 0, 1);
    BN_DEFINE(bn4, 6,
              0, 0, 0, 0, 0, 1);

    BN_PRINT(bn1)
    BN_PRINT(bn2)
    BN_PRINT(bn3) BN_PRINT(bn4)

        LOG("bn1 == bn2: %d[0]\r\n", bn_cmp_e(bn1, bn2));
    LOG("bn2 == bn2: %d[1]\r\n", bn_cmp_e(bn2, bn2));
    LOG("bn3 == bn4: %d[1]\r\n", bn_cmp_e(bn3, bn4));

    LOG("bn1 < bn2: %d[1]\r\n", bn_cmp_l(bn1, bn2));
    LOG("bn2 < bn1: %d[0]\r\n", bn_cmp_l(bn2, bn1));
    LOG("bn2 < bn2: %d[0]\r\n", bn_cmp_l(bn2, bn2));
    LOG("bn3 < bn4: %d[0]\r\n", bn_cmp_l(bn3, bn4));

    LOG("bn1 <= bn2: %d[1]\r\n", bn_cmp_le(bn1, bn2));
    LOG("bn2 <= bn1: %d[0]\r\n", bn_cmp_le(bn2, bn1));
    LOG("bn3 <= bn4: %d[1]\r\n", bn_cmp_le(bn3, bn4));
    LOG("bn4 <= bn3: %d[1]\r\n", bn_cmp_le(bn4, bn3));

    LOG("bn1 > bn2: %d[0]\r\n", bn_cmp_b(bn1, bn2));
    LOG("bn2 > bn1: %d[1]\r\n", bn_cmp_b(bn2, bn1));
    LOG("bn2 > bn2: %d[0]\r\n", bn_cmp_b(bn2, bn2));
    LOG("bn3 > bn4: %d[0]\r\n", bn_cmp_b(bn3, bn4));

    LOG("bn1 >= bn2: %d[0]\r\n", bn_cmp_be(bn1, bn2));
    LOG("bn2 >= bn1: %d[1]\r\n", bn_cmp_be(bn2, bn1));
    LOG("bn2 >= bn2: %d[1]\r\n", bn_cmp_be(bn2, bn2));
    LOG("bn3 >= bn4: %d[1]\r\n", bn_cmp_be(bn3, bn4));
}
void bn_mod_mock()
{
    BN_DEFINE(bn1, CRSA_BN_CNT,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF)
    //   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    //   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    BN_DEFINE(bn2, CRSA_CNT_U16,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF,
              0x1234, 0x5678, 0x9ABC, 0xFFFF)
    BN_DEFINE(bnret, CRSA_CNT_U16)
    BN_PRINT(bn1) BN_PRINT(bn2) BN_PRINT(bnret)

    bn_mod(bn1, bn2, bnret); BN_PRINT(bnret);
    bn_mod(bn2, bn1, bnret); BN_PRINT(bnret);
    bn_mod(bn1, bn1, bnret); BN_PRINT(bnret);
    bn1->val[4]--; bn_mod(bn1, bn2, bnret); BN_PRINT(bnret);
    bn1->val[4] += 2; bn_mod(bn1, bn2, bnret); BN_PRINT(bnret);
    bn_mod(bn1, bn2, bn2); BN_PRINT(bn2);
    bn_mod(bn1, bn1, bn2); BN_PRINT(bn2);
    bn_mod(bn1, bn1, bn1); BN_PRINT(bn1);
    bn_mod(bn1, bnret, bn1); BN_PRINT(bn1);
    // bn_mod(bn1, bn2, bn1); BN_PRINT(bn1);    //FATAL: modulus = 0
}
#if 0
int main()
{
    // bn_define_mock();
    // bn_cmp_mock();
    bn_num_mock();
    // bn_minus_mock();
    // bn_add_mock();
    // bn_mult_mock();
    // bn_mod_mock();
    return 0;
}
#endif
