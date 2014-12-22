
#pragma once

#include <Windows.h>

#ifndef BASIC_LIB_PP_API
	#ifdef BASICLIBPP_EXPORTS
		#define BASIC_LIB_PP_API __declspec(dllexport)
	#else
		#define BASIC_LIB_PP_API __declspec(dllimport)
	#endif
#endif

/************************************************************************/

// Note: The int type returns 0 means success, not 0 means error.

typedef int (* zzyLzma_pfn_Read)(void *userData, void *buf, size_t *size);
    /* Returns: result. (result != SZ_OK) means error.
       if (input(*size) != 0 && output(*size) == 0) means end_of_stream.
       (output(*size) < input(*size)) is allowed */
typedef size_t (* zzyLzma_pfn_Write)(void *userData, const void *buf, size_t size);
    /* Returns: result - the number of actually written bytes.
       (result < size) means error */
typedef int (* zzyLzma_pfn_Progress)(void *userData, unsigned __int64 inSize, unsigned __int64 outSize);
    /* Returns: result. (result != SZ_OK) means break.
       Value (UInt64)(Int64)-1 for size means unknown value. */

/************************************************************************/

BASIC_LIB_PP_API void * zzyLzmaEnc_create();
BASIC_LIB_PP_API void zzyLzmaEnc_destroy(void *ctx);

BASIC_LIB_PP_API
int zzyLzmaEnc_setProps(
	void *ctx,
	int level, /* 0 <= level <= 9, default = 5 */
	int nBlock /* 1 <= nBlock <= 32, default = 1 */);

BASIC_LIB_PP_API
int zzyLzmaEnc_encode(
	void *ctx,
	unsigned __int64 totalLength, /* Value (UInt64)(Int64)-1 for size means unknown value. */
	void *userData,
	zzyLzma_pfn_Read fnRead,
	zzyLzma_pfn_Write fnWrite,
	zzyLzma_pfn_Progress fnProgress);

BASIC_LIB_PP_API
int zzyLzmaDec_decode(
	void *userData,
	zzyLzma_pfn_Read fnRead,
	zzyLzma_pfn_Write fnWrite);

/************************************************************************/

BASIC_LIB_PP_API
void zzyLzma_freeBuffer(void *ptr);

BASIC_LIB_PP_API
int zzyLzma_compress(
	const void *inData,
	size_t inDataLength,
	int level, /* 0 <= level <= 9, default = 5 */
	int nBlock, /* 1 <= nBlock <= 32, default = 1 */
	void **outData,
	size_t *outDataLength);

BASIC_LIB_PP_API
int zzyLzma_decompress(
	const void *inData,
	size_t inDataLength,
	void **outData,
	size_t *outDataLength);

BASIC_LIB_PP_API unsigned __int64 zzyLzma_getDecompressedLength(unsigned char header[9]);
