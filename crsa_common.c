#include "crsa_common.h"

void LOG_BYTE(const char *str, const uint8_t *src, uint16_t size){
    printf("%s[%d]", str, size);
    for (uint16_t i = 0; i < size; ++i)
        printf(" %02X", src[i]);
    printf("\r\n");
}

void LOG_SHORT(const char *str, const uint16_t *src, uint16_t size){
    printf("%s[%02d]", str, size);
    for (uint16_t i = 0; i < size; ++i)
        printf(" %04X", src[i]);
    printf("\r\n");
}
