#include <string.h>
#include "crsa_common.h"
#include "bignum.h"
#include "crsa.h"

typedef struct _CRSA_KEY_T
{
    const BN_T *exp;
    const BN_T *modulus;
} CRSA_KEY_T;

//pub e 0x10001, PKCS#1的建议值
static const uint16_t gs_buf_E[CNT_OF_BN_BUF] = {
    2, CNT_OF_BN_VAL,
    1, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0};
static const uint16_t gs_buf_D[CNT_OF_BN_BUF] = {
    16, CNT_OF_BN_VAL,
    0x5FF9, 0x618F, 0x728B, 0x11A9, 0xC616, 0x1078, 0x86E6, 0x3D79,
    0xE2FC, 0x577F, 0xA070, 0x7C5F, 0x6446, 0xE888, 0x5B0A, 0x08A2};
static const uint16_t gs_buf_N[CNT_OF_BN_BUF] = {
    16, CNT_OF_BN_VAL,
    0xA10B, 0xE7C5, 0xD795, 0x09DA, 0x9256, 0x209C, 0xED14, 0x4826,
    0x3FDD, 0x3B4B, 0x0AB3, 0xC5A8, 0xB135, 0x8C88, 0x951D, 0x1594};
// const uint16_t gs_buf_D[CNT_OF_BN_BUF] = {
//     8, CNT_OF_BN_VAL,
//     0x0E81, 0x6E2E, 0xBC1D, 0xCBDC, 0x4C5C, 0x5A5D, 0x7169, 0x17B2};
// const uint16_t gs_buf_N[CNT_OF_BN_BUF] = {
//     8, CNT_OF_BN_VAL,
//     0xED83, 0x7EA2, 0x6663, 0x93E1, 0x3B05, 0x141F, 0xE0BE, 0x1DDE};

#define CRSA_PADDING (BYTE_OF_BN_VAL - 1) //确保padding后的明文m小于mudulus

static const CRSA_KEY_T pubkey = {
    CNST_BN_PTR(gs_buf_E),
    CNST_BN_PTR(gs_buf_N)};
static const CRSA_KEY_T prikey = {
    CNST_BN_PTR(gs_buf_D),
    CNST_BN_PTR(gs_buf_N)};

int32_t crsa_init()
{
    int16_t ret = 0;
    UASSERT(BN_NOT_EMPTY(CNST_BN_PTR(gs_buf_E)), ret = CRSA_EC_KEY)
    UASSERT(BN_NOT_EMPTY(CNST_BN_PTR(gs_buf_D)), ret = CRSA_EC_KEY)
    UASSERT(BN_NOT_EMPTY(CNST_BN_PTR(gs_buf_N)), ret = CRSA_EC_KEY)
    ret = bn_init();
__exit:
    return ret;
}

#define CRSA_PADDING_TOTAL_SIZE(_size) ((_size + CRSA_PADDING - 1) / CRSA_PADDING * BYTE_OF_BN_VAL)
#define CRSA_ORIGIN_SIZE(_size) (_size / BYTE_OF_BN_VAL * CRSA_PADDING)
int32_t crsa_encrypt_base(const CRSA_KEY_T *key, const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    FASSERT(key && src && dst)
    LOGRSA("%s(%d) - entry\r\n", __FUNCTION__, __LINE__);

    int32_t ret;
    BASE_BN_DEFINE(bn_padding, CNT_OF_BN_VAL)

    UASSERT(src_size, ret = CRSA_EC_SRC_SIZE)
    ret = CRSA_PADDING_TOTAL_SIZE(src_size);
    UASSERT(dst_size >= ret, ret = CRSA_EC_DST_SIZE)

    for (; src_size >= CRSA_PADDING; src_size -= CRSA_PADDING)
    {
        bn_padding->val[CNT_OF_BN_VAL - 1] = 0;
        memcpy(bn_padding->val, src, CRSA_PADDING);
        BN_SET_CNT(bn_padding)
        src += CRSA_PADDING;
        bn_modexp(bn_padding, key->exp, key->modulus, bn_padding);
        memcpy(dst, bn_padding->val, BYTE_OF_BN_VAL);
        dst += BYTE_OF_BN_VAL;
    }
    if (src_size)
    {
        BN_RST(bn_padding)
        memcpy(bn_padding->val, src, src_size);
        BN_SET_CNT(bn_padding)
        bn_modexp(bn_padding, key->exp, key->modulus, bn_padding);
        memcpy(dst, bn_padding->val, BYTE_OF_BN_VAL);
    }

__exit:
    LOGRSA("%s(%d) - exit:%d\r\n", __FUNCTION__, __LINE__, ret);
    return ret;
}
int32_t crsa_decode_base(const CRSA_KEY_T *key, const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    FASSERT(key && src && dst)
    LOGRSA("%s(%d) - entry\r\n", __FUNCTION__, __LINE__);

    int32_t ret = 0;
    BASE_BN_DEFINE(bn_padding, CNT_OF_BN_VAL)

    UASSERT(src_size && !(src_size % BYTE_OF_BN_VAL), ret = CRSA_EC_SRC_SIZE)
    ret = CRSA_ORIGIN_SIZE(src_size);
    UASSERT(dst_size >= ret, ret = CRSA_EC_DST_SIZE)

    for (; src_size; src_size -= BYTE_OF_BN_VAL)
    {
        memcpy(bn_padding->val, src, BYTE_OF_BN_VAL);
        BN_SET_CNT(bn_padding);
        bn_modexp(bn_padding, key->exp, key->modulus, bn_padding);
        UASSERT(!(bn_padding->val[CNT_OF_BN_VAL - 1] >> (BITS_OF_BN_VAL / 2)), ret = CRSA_EC_CIPHERTEXT)
        memcpy(dst, bn_padding->val, CRSA_PADDING);
        src += BYTE_OF_BN_VAL;
        dst += CRSA_PADDING;
    }
__exit:
    LOGRSA("%s(%d) - exit:%d\r\n", __FUNCTION__, __LINE__, ret);
    return ret;
}
int32_t crsa_encrypt_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    return crsa_encrypt_base(&prikey, src, (src_size), dst, (dst_size));
}
int32_t crsa_encrypt_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    return crsa_encrypt_base(&pubkey, src, (src_size), dst, (dst_size));
}
int32_t crsa_decode_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    return crsa_decode_base(&prikey, src, (src_size), dst, (dst_size));
}
int32_t crsa_decode_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size)
{
    return crsa_decode_base(&pubkey, src, (src_size), dst, (dst_size));
}
//sign
//verify
//genkey
