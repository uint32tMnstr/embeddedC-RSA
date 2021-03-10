#include <string.h>
#include "crsa_common.h"
#include "bignum.h"
#include "crsa.h"

typedef struct _CRSA_KEY_T {
    const BN_T *exp;
    const BN_T *modulus;
} CRSA_KEY_T;

//pub e 0x10001, PKCS#1的建议值
static const uint16_t gs_buf_E[CRSA_BN_BUF_CNT] = {
    2, CRSA_CNT_U16,
    1, 1, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0};
static const uint16_t gs_buf_D[CRSA_BN_BUF_CNT] = {
    16, CRSA_CNT_U16,
    0x5FF9, 0x618F, 0x728B, 0x11A9, 0xC616, 0x1078, 0x86E6, 0x3D79, 
    0xE2FC, 0x577F, 0xA070, 0x7C5F, 0x6446, 0xE888, 0x5B0A, 0x08A2};
static const uint16_t gs_buf_N[CRSA_BN_BUF_CNT] = {
    16, CRSA_CNT_U16,
    0xA10B, 0xE7C5, 0xD795, 0x09DA, 0x9256, 0x209C, 0xED14, 0x4826,
    0x3FDD, 0x3B4B, 0x0AB3, 0xC5A8, 0xB135, 0x8C88, 0x951D, 0x1594};
// const uint16_t gs_buf_D[CRSA_BN_BUF_CNT] = {
//     8, CRSA_CNT_U16,
//     0x0E81, 0x6E2E, 0xBC1D, 0xCBDC, 0x4C5C, 0x5A5D, 0x7169, 0x17B2};
// const uint16_t gs_buf_N[CRSA_BN_BUF_CNT] = {
//     8, CRSA_CNT_U16,
//     0xED83, 0x7EA2, 0x6663, 0x93E1, 0x3B05, 0x141F, 0xE0BE, 0x1DDE};

#define CRSA_PADDING_U8   (CRSA_CNT_U8 - 1)

static const CRSA_KEY_T pubkey = {
    BN_CNST_TYPE(gs_buf_E),
    BN_CNST_TYPE(gs_buf_N)};
static const CRSA_KEY_T prikey = {
    BN_CNST_TYPE(gs_buf_D),
    BN_CNST_TYPE(gs_buf_N)};

int32_t crsa_init(){
    int16_t ret = 0;
    UASSERT(BN_IS_NOT_EMPTY(BN_CNST_TYPE(gs_buf_E)), ret = CRSA_EC_KEY)
    UASSERT(BN_IS_NOT_EMPTY(BN_CNST_TYPE(gs_buf_D)), ret = CRSA_EC_KEY)
    UASSERT(BN_IS_NOT_EMPTY(BN_CNST_TYPE(gs_buf_N)), ret = CRSA_EC_KEY)
__exit:
    return ret;
}

static void crsa_moden(const CRSA_KEY_T *key, const uint16_t *src, uint16_t *dst)
{
    BN_DEFINE(exp, CRSA_CNT_U16)
    BN_DEFINE(dst_copy, CRSA_BN_CNT)
    BN_DEFINE(ans, CRSA_BN_CNT, 1)

    BN_COPY(exp, BN_CNST_TYPE(key->exp))
    memcpy(dst_copy->val, src, CRSA_CNT_U16 * sizeof(uint16_t));
    BN_SET_CNT(dst_copy)
    // BN_PRINT(exp)
    // LOG("src "); BN_PRINT(dst_copy)
    // BN_PRINT(ans)
    
    if(!BN_IS_NOT_EMPTY(dst_copy)){
        memset(dst, 0, CRSA_CNT_U16*sizeof(uint16_t));
        return;
    }

    //快速幂算法
    // REF: https://www.cnblogs.com/Dfkuaid-210/p/12115238.html
    bn_mod(dst_copy, key->modulus, dst_copy);
    while(exp->cnt){
        if(exp->val[0] & 1){
            bn_mult(ans, dst_copy, ans);
            bn_mod(ans, key->modulus, ans);
        }
        bn_mult(dst_copy, dst_copy, dst_copy);
        // BN_PRINT(dst_copy)
        bn_mod(dst_copy, key->modulus, dst_copy);
        // BN_PRINT(dst_copy)
        bn_devide_num(exp, 2, exp);
        // BN_PRINT(exp)
    }
    // LOG("ret "); BN_PRINT(ans)
    memcpy(dst, ans->val, CRSA_CNT_U16*sizeof(uint16_t));
}
#define CRSA_PADDING_SIZE(_size)    ((_size + CRSA_PADDING_U8 - 1) / CRSA_PADDING_U8 * CRSA_CNT_U8)
#define CRSA_PLAIN_SIZE(_size)      (_size / CRSA_CNT_U8 * CRSA_PADDING_U8)
int32_t crsa_encrypt_base(const CRSA_KEY_T *key, const char *src, int32_t src_size, char *dst, int32_t dst_size){
    FASSERT(key && src && dst)

    int32_t ret;
    BN_DEFINE(bn_src_padding, CRSA_CNT_U16)

    UASSERT(src_size, ret = CRSA_EC_SRC_SIZE)
    ret = CRSA_PADDING_SIZE(src_size);
    UASSERT(dst_size >= ret, ret = CRSA_EC_DST_SIZE)

    for (; src_size >= CRSA_PADDING_U8; src_size -= CRSA_PADDING_U8) {
        memcpy(bn_src_padding->val, src, CRSA_PADDING_U8);
        src += CRSA_PADDING_U8;
        bn_src_padding->val[CRSA_CNT_U16 - 1] &= 0xFF; //确保padding后的明文m小于mudulus
        BN_SET_CNT(bn_src_padding)
        bn_modexp(bn_src_padding, key->exp, key->modulus, bn_src_padding);
        memcpy(dst, bn_src_padding->val, CRSA_CNT_U8);
        dst += CRSA_CNT_U8;
    }
    if (src_size) {
        BN_RST(bn_src_padding)
        memcpy(bn_src_padding->val, src, src_size);
        BN_SET_CNT(bn_src_padding)
        bn_modexp(bn_src_padding, key->exp, key->modulus, bn_src_padding);
        memcpy(dst, bn_src_padding->val, CRSA_CNT_U8);
    }

__exit:
    return ret;
}
int32_t crsa_decode_base(const CRSA_KEY_T *key, const char *src, int32_t src_size, char *dst, int32_t dst_size){
    FASSERT(key && src && dst)
    
    int32_t ret = 0;
    BN_DEFINE(bn_dst, CRSA_CNT_U16)

    UASSERT(src_size && !(src_size % CRSA_CNT_U8), ret = CRSA_EC_SRC_SIZE)
    ret = CRSA_PLAIN_SIZE(src_size);
    UASSERT(dst_size >= ret, ret = CRSA_EC_DST_CNT)

    for (; src_size; src_size -= CRSA_CNT_U8) {
        memcpy(bn_dst->val, src, CRSA_CNT_U8);
        BN_SET_CNT(bn_dst);
        bn_modexp(bn_dst, key->exp, key->modulus, bn_dst);
        UASSERT(!(bn_dst->val[CRSA_CNT_U16 - 1] & 0xFF00), ret = CRSA_EC_CIPHERTEXT)
        memcpy(dst, bn_dst->val, CRSA_PADDING_U8);
        src += CRSA_CNT_U8;
        dst += CRSA_PADDING_U8;
    }
__exit:
    return ret;
}
int32_t crsa_encrypt_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size){
    return crsa_encrypt_base(&prikey, src, src_size, dst, dst_size);
}
int32_t crsa_encrypt_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size){
    return crsa_encrypt_base(&pubkey, src, src_size, dst, dst_size);
}
int32_t crsa_decode_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size){
    return crsa_decode_base(&prikey, src, src_size, dst, dst_size);
}
int32_t crsa_decode_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size){
    return crsa_decode_base(&pubkey, src, src_size, dst, dst_size);
}
//sign
//verify
//genkey
