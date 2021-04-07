#ifndef _CRSA_H
#define _CRSA_H

#ifdef __cplusplus
extern "C"
{
#endif

#define LOGRSA(...) LOG(__VA_ARGS__)

    int32_t crsa_init(void);
    int32_t crsa_encrypt_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size);
    int32_t crsa_encrypt_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size);
    int32_t crsa_decode_pri(const char *src, int32_t src_size, char *dst, int32_t dst_size);
    int32_t crsa_decode_pub(const char *src, int32_t src_size, char *dst, int32_t dst_size);

#ifdef __cplusplus
};
#endif

#endif //_CRSA_H