
#ifndef _CRSA_COMMON_H
#define _CRSA_COMMON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#define CRSA_KEY_BITS (256)

#define UASSERT(con, ...) \
    {                     \
        if (!(con))       \
        {                 \
            __VA_ARGS__;  \
            goto __exit;  \
        }                 \
    }

#define FASSERT(con)                                                    \
    {                                                                   \
        if (!(con))                                                     \
        {                                                               \
            LOG("[FATAL] %s:%s(%d)\r\n", __FILE__, __FUNCTION__, __LINE__); \
            while (1)                                                   \
                ;                                                       \
        }                                                               \
    }

#define _CRSA_LOG

#ifndef BOOL
    #define BOOL int8_t
#endif
#ifndef FALSE
    #define FALSE (0)
#endif
#ifndef TRUE
    #define TRUE (1)
#endif
#if (TRUE == FALSE)
    #err "TRUE same as FALSE"
#endif
#ifndef MIN
    #define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#endif
#ifndef MAX
    #define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif

// ERROR CODE
#define CRSA_OK             (int16_t)0
#define CRSA_EC_BIT_MASK    (int16_t)0x8000
#define CRSA_EC_PARAM       (int16_t)0x8001
#define CRSA_EC_KEY         (int16_t)0x8002
#define CRSA_EC_KEY_BITS    (int16_t)0x8011
#define CRSA_EC_OPT_BITS    (int16_t)0x8012
#define CRSA_EC_BN_UNIT     (int16_t)0x8013
#define CRSA_EC_SRC_SIZE    (int16_t)0x8013
#define CRSA_EC_DST_SIZE    (int16_t)0x8014
#define CRSA_EC_CIPHERTEXT  (int16_t)0x8021

#ifdef _CRSA_LOG
    #include <stdio.h>
    #define LOG printf
    #define LOG_BYTE(...)   log_byte(__VA_ARGS__)
    #define LOG_SHORT(...)  log_short(__VA_ARGS__)
    void log_byte  (const char *str, const uint8_t *src, uint16_t size);
    void log_short (const char *str, const uint16_t *src, uint16_t size);
#else
    #ifndef LOG
        #define LOG 
    #endif
    #ifndef LOG_BYTE
        #define LOG_BYTE(...)
    #endif
    #ifndef LOG_SHORT
        #define LOG_SHORT(...)
    #endif
#endif

#ifdef __cplusplus
};
#endif

#endif //_CRSA_COMMON_H
