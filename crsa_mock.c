#include "crsa_common.h"
#include "bignum.h"
#include "crsa.h"
#include <stdlib.h>

#define CRSA_PADDING   (BYTE_OF_BN_VAL - 1)
#define SRC_MAX_CNT     (256)
#define DST_MAX_SIZE    ((SRC_MAX_CNT * sizeof(uint32_t) + CRSA_PADDING - 1) / CRSA_PADDING * BYTE_OF_BN_VAL)
#define DST_MAX_CNT     ((DST_MAX_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t))
void RSA_loop_mock(void){
    int loop = 0;
    srand(354);
    while(1){
        int32_t src[SRC_MAX_CNT]  = {0};
        int32_t dst[DST_MAX_CNT]  = {0};
        int32_t src_size = 0, dst_size;

        src_size = rand() % SRC_MAX_CNT;
        while(!src_size)
            src_size = rand() % SRC_MAX_CNT;
        for(uint32_t i = 0; i < src_size; ++i)
            src[i] = rand()<<16 + rand();
        src[0] |= 1;    //do not encrypt empty plain text
        src_size *= sizeof(uint32_t);
        dst_size = crsa_encrypt_pub((const char *)src, src_size , (char *)dst, DST_MAX_SIZE);
        if(dst_size < 0){
            LOG("encrypt error: 0x%X\r\n", dst_size);
            LOG_BYTE("SRC", (const char *)src, src_size);
            return;
        }else{
            LOG("src[%d] => dst[%d]\r\n", src_size, dst_size);
        }
        dst_size = crsa_decode_pri((const char *)dst, dst_size, (char *)dst, DST_MAX_SIZE);
        if(dst_size < 0){
            LOG("decrypt error: 0x%X\r\n", dst_size);
            LOG_BYTE("SRC", (const char *)src, src_size);
            LOG_BYTE("DST", (const char *)dst, src_size);
            return;
        }
        src_size /= sizeof(uint32_t);
        for(uint32_t i = 0; i < src_size; ++i){
            if(dst[i] != src[i]){
                LOG_BYTE("ERR", (const char *)src, src_size); 
                LOG_BYTE("DST", (const char *)dst, src_size);
                LOG("i = %d, dst_cnt = %d\r\n", i, dst_size);
                return;
            }
        }
        LOG("loop %d\r\n", loop++);
    }
}

int main()
{
    // RSA_loop_mock();
    int16_t cnt;
    const char *str1 = "[CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.\r\nrepeat: [CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.";
    const char *str2 = "[CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.\r\nrepeat: [CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.";
    int16_t strsize1 = strlen(str1);
    int16_t strsize2 = strlen(str2);
#define CRSA_DST_SIZE   (BYTE_OF_BN_VAL*10)
    char dst[CRSA_DST_SIZE] = {0};

    FASSERT(CRSA_DST_SIZE >= strsize1)
    
    LOG("======encrypt by public key======\r\n");
    LOG("plain text: \r\n%s\r\n", str1);
    // LOG_BYTE("plain", str, strsize1);
    cnt = crsa_encrypt_pub(str1, strsize1, dst, CRSA_DST_SIZE);
    if(cnt < 0){
        LOG("encrypt failed: %04X\r\n", cnt);
    }else{
        LOG_BYTE("cipher", dst, cnt);
        cnt = crsa_decode_pri(dst, cnt, dst, CRSA_DST_SIZE);
        if(cnt < 0){
            LOG("decode failed: %04X\r\n", cnt);
        }else{
            // LOG_BYTE("decode", dst, cnt);
            dst[cnt] = 0;
            LOG("decode text: \r\n%s\r\n", dst);
        }
    }

    LOG("======encrypt by private key======\r\n");
    LOG("plain text: \r\n%s\r\n", str2);
    cnt = crsa_encrypt_pri(str2, strsize2, dst, CRSA_DST_SIZE);
    if(cnt < 0){
        LOG("encrypt failed: %04X\r\n", cnt);
    }else{
        LOG_BYTE("cipher", dst, cnt);
        cnt = crsa_decode_pub(dst, cnt, dst, CRSA_DST_SIZE);
        if(cnt < 0){
            LOG("decode failed: %04X\r\n", cnt);
        }else{
            // LOG_BYTE("decode", dst, cnt);
            dst[cnt] = 0;
            LOG("decode text: \r\n%s\r\n", dst);
        }
    }
    return 0;
}