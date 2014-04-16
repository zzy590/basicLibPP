
#ifndef LZMA_CRT_FUNC_ZZY
#define LZMA_CRT_FUNC_ZZY

#include <windows.h>

#if 1 // use crt
    #define my_memcpy memcpy
    #define my_memmove memmove
    #define my_memset memset
#else
    void my_memcpy(void *dst,const void *src,size_t size);
    void my_memmove(void *dst,const void *src,size_t size);
    void my_memset(void * dst,unsigned char c,size_t n);
#endif

#endif // LZMA_CRT_FUNC_ZZY
