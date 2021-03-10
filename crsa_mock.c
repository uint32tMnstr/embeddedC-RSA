#include "crsa_common.h"
#include "bignum.h"
#include "crsa.h"

int main()
{
    int16_t cnt;
    const char *str1 = "[CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.\r\nrepeat: [CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.";
    const char *str2 = "[CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.\r\nrepeat: [CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.";
    int16_t strsize1 = strlen(str1);
    int16_t strsize2 = strlen(str2);
#define CRSA_DST_SIZE   (CRSA_CNT_U8*10)
    char dst[CRSA_DST_SIZE] = {0};

    FASSERT(CRSA_DST_SIZE >= strsize1)
    
    LOG("CRSA TEST\r\n");
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