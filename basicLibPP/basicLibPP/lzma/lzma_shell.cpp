
#include <Windows.h>

#include "lzmaLib/Lzma2Enc.h"
#include "lzmaLib/Lzma2Dec.h"

#include "lzma_shell.h"

/************************************************************************/

static void *alloc_small(void *p, size_t size)
{
	try
	{
		return new char [size];
	}
	catch (...)
	{
		return NULL;
	}
}

static void free_small(void *p, void *address) /* address can be 0 */
{
	if (address)
	{
		delete [] ((char *)address);
	}
}

static void *alloc_big(void *p, size_t size)
{
	return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

static void free_big(void *p, void *address) /* address can be 0 */
{
	if (address)
	{
		VirtualFree(address, 0, MEM_RELEASE);
	}
}

static ISzAlloc g_Alloc = {alloc_small,free_small};
static ISzAlloc g_BigAlloc = {alloc_big,free_big};

/************************************************************************/

void * zzyLzmaEnc_create()
{
	return Lzma2Enc_Create(&g_Alloc,&g_BigAlloc);
}

void zzyLzmaEnc_destroy(void *ctx)
{
	Lzma2Enc_Destroy(ctx);
}

int zzyLzmaEnc_setProps(
	void *ctx,
	int level, /* 0 <= level <= 9, default = 5 */
	int nBlock /* 1 <= nBlock <= 32, default = 1 */)
{
	CLzma2EncProps props;
	Lzma2EncProps_Init(&props);
	props.lzmaProps.level = level;
	props.numBlockThreads = nBlock;
	Lzma2EncProps_Normalize(&props);
	return Lzma2Enc_SetProps(ctx,&props);
}

typedef struct
{
	ISeqInStream inStream;
	zzyLzma_pfn_Read userRead;
	void *userData;
} ISeqInStreamWithData;

typedef struct
{
	ISeqOutStream outStream;
	zzyLzma_pfn_Write userWrite;
	void *userData;
} ISeqOutStreamWithData;

typedef struct
{
	ICompressProgress progress;
	zzyLzma_pfn_Progress userProgress;
	void *userData;
} ICompressProgressWithData;

static SRes internalRead(void *p, void *buf, size_t *size)
{
	ISeqInStreamWithData *pIn = CONTAINING_RECORD(p,ISeqInStreamWithData,inStream);
	return pIn->userRead(pIn->userData,buf,size);
}

static size_t internalWrite(void *p, const void *buf, size_t size)
{
	ISeqOutStreamWithData *pOut = CONTAINING_RECORD(p,ISeqOutStreamWithData,outStream);
	if (pOut->userWrite)
	{
		return pOut->userWrite(pOut->userData,buf,size);
	}
	return size;
}

static SRes internalProgress(void *p, UInt64 inSize, UInt64 outSize)
{
	ICompressProgressWithData *pProgress = CONTAINING_RECORD(p,ICompressProgressWithData,progress);
	if (pProgress->userProgress)
	{
		return pProgress->userProgress(pProgress->userData,inSize,outSize);
	}
	return SZ_OK;
}

int zzyLzmaEnc_encode(
	void *ctx,
	unsigned __int64 totalLength, /* Value (UInt64)(Int64)-1 for size means unknown value. */
	void *userData,
	zzyLzma_pfn_Read fnRead,
	zzyLzma_pfn_Write fnWrite,
	zzyLzma_pfn_Progress fnProgress)
{
	ISeqInStreamWithData inStream;
	ISeqOutStreamWithData outStream;
	ICompressProgressWithData progress;
	inStream.inStream.Read = internalRead;
	inStream.userRead = fnRead;
	inStream.userData = userData;
	outStream.outStream.Write = internalWrite;
	outStream.userWrite = fnWrite;
	outStream.userData = userData;
	progress.progress.Progress = internalProgress;
	progress.userProgress = fnProgress;
	progress.userData = userData;
	Byte prop = Lzma2Enc_WriteProperties(ctx);
	Byte header[9];
	header[0] = prop;
	for (int i=0;i<8;++i)
	{
		header[i+1] = (Byte)(totalLength >> (8 * i));
	}
	size_t ret = fnWrite(userData,header,sizeof(header));
	if (ret != sizeof(header))
	{
		return SZ_ERROR_WRITE;
	}
	return Lzma2Enc_Encode(ctx,&outStream.outStream,&inStream.inStream,&progress.progress);
}

#define IN_BUF_SIZE (1 << 16)
#define OUT_BUF_SIZE (1 << 16)

static SRes Decode2(CLzma2Dec *state, void *userData, zzyLzma_pfn_Write outStream, zzyLzma_pfn_Read inStream, UInt64 unpackSize)
{
	int thereIsSize = (unpackSize != (UInt64)(Int64)-1);
	Byte inBuf[IN_BUF_SIZE];
	Byte outBuf[OUT_BUF_SIZE];
	size_t inPos = 0, inSize = 0, outPos = 0;
	Lzma2Dec_Init(state);
	for (;;)
	{
		if (inPos == inSize)
		{
			inSize = IN_BUF_SIZE;
			RINOK(inStream(userData, inBuf, &inSize));
			inPos = 0;
		}
		{
			SRes res;
			SizeT inProcessed = inSize - inPos;
			SizeT outProcessed = OUT_BUF_SIZE - outPos;
			ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
			ELzmaStatus status;
			if (thereIsSize && outProcessed > unpackSize)
			{
				outProcessed = (SizeT)unpackSize;
				finishMode = LZMA_FINISH_END;
			}

			res = Lzma2Dec_DecodeToBuf(state, outBuf + outPos, &outProcessed,
				inBuf + inPos, &inProcessed, finishMode, &status);
			inPos += inProcessed;
			outPos += outProcessed;
			unpackSize -= outProcessed;

			if (outStream)
				if (outStream(userData, outBuf, outPos) != outPos)
					return SZ_ERROR_WRITE;

			outPos = 0;

			if (res != SZ_OK || thereIsSize && unpackSize == 0)
				return res;

			if (inProcessed == 0 && outProcessed == 0)
			{
				if (thereIsSize || status != LZMA_STATUS_FINISHED_WITH_MARK)
					return SZ_ERROR_DATA;
				return res;
			}
		}
	}
}

static SRes InStream_Read(void *userData, zzyLzma_pfn_Read fnRead, void *buf, size_t size)
{
	while (size != 0)
	{
		size_t processed = size;
		RINOK(fnRead(userData, buf, &processed));
		if (processed == 0)
			return SZ_ERROR_READ;
		buf = (void *)((Byte *)buf + processed);
		size -= processed;
	}
	return SZ_OK;
}

int zzyLzmaDec_decode(
	void *userData,
	zzyLzma_pfn_Read fnRead,
	zzyLzma_pfn_Write fnWrite)
{
	UInt64 unpackSize;
	int i;
	SRes res = 0;

	CLzma2Dec state;

	/* header: 1 bytes of LZMA2 properties and 8 bytes of uncompressed size */
	unsigned char header[9];

	/* Read and parse header */

	RINOK(InStream_Read(userData, fnRead, header, sizeof(header)));

	unpackSize = 0;
	for (i = 0; i < 8; i++)
		unpackSize += (UInt64)header[1 + i] << (i * 8);

	Lzma2Dec_Construct(&state);
	RINOK(Lzma2Dec_Allocate(&state, header[0], &g_Alloc));
	res = Decode2(&state, userData, fnWrite, fnRead, unpackSize);
	Lzma2Dec_Free(&state, &g_Alloc);
	return res;
}

/************************************************************************/

typedef struct
{
	const void *inData;
	size_t inDataLength;
	size_t inDataPos;
	void *outData;
	size_t outDataLength;
	size_t outDataPos;
} BUFFER_COMPRESS_INFO;

static int bufferRead(void *userData, void *buf, size_t *size)
{
	BUFFER_COMPRESS_INFO *info = (BUFFER_COMPRESS_INFO *)userData;
	if (*size > info->inDataLength-info->inDataPos)
	{
		*size = info->inDataLength-info->inDataPos;
	}
	memcpy(buf,(char *)info->inData+info->inDataPos,*size);
	info->inDataPos += *size;
	return SZ_OK;
}

static size_t bufferWrite(void *userData, const void *buf, size_t size)
{
	BUFFER_COMPRESS_INFO *info = (BUFFER_COMPRESS_INFO *)userData;
	if (size > info->outDataLength-info->outDataPos)
	{
		size_t tmpLength = 2*info->outDataLength;
		while (size > tmpLength-info->outDataPos)
		{
			tmpLength *= 2;
		}
		void *tmpBuffer = alloc_big(NULL,tmpLength);
		if (NULL == tmpBuffer)
		{
			return 0;
		}
		memcpy(tmpBuffer,info->outData,info->outDataPos);
		free_big(NULL,info->outData);
		info->outData = tmpBuffer;
		info->outDataLength = tmpLength;
	}
	memcpy((char *)info->outData+info->outDataPos,buf,size);
	info->outDataPos += size;
	return size;
}

void zzyLzma_freeBuffer(void *ptr)
{
	free_big(NULL,ptr);
}

int zzyLzma_compress(
	const void *inData,
	size_t inDataLength,
	int level, /* 0 <= level <= 9, default = 5 */
	int nBlock, /* 1 <= nBlock <= 32, default = 1 */
	void **outData,
	size_t *outDataLength)
{
	void *ctx = zzyLzmaEnc_create();
	if (NULL == ctx)
	{
		return SZ_ERROR_MEM;
	}
	int res = zzyLzmaEnc_setProps(ctx,level,nBlock);
	if (res != SZ_OK)
	{
		goto _ec;
	}
	BUFFER_COMPRESS_INFO compressInfo;
	compressInfo.inData = inData;
	compressInfo.inDataLength = inDataLength;
	compressInfo.inDataPos = 0;
	compressInfo.outData = alloc_big(NULL,inDataLength);
	compressInfo.outDataLength = inDataLength;
	compressInfo.outDataPos = 0;
	if (NULL == compressInfo.outData)
	{
		res = SZ_ERROR_MEM;
		goto _ec;
	}
	res = zzyLzmaEnc_encode(ctx,inDataLength,&compressInfo,bufferRead,bufferWrite,NULL);
	if (SZ_OK == res)
	{
		*outData = compressInfo.outData;
		*outDataLength = compressInfo.outDataPos;
	}
	else
	{
		free_big(NULL,compressInfo.outData);
	}
_ec:
	zzyLzmaEnc_destroy(ctx);
	return res;
}

int zzyLzma_decompress(
	const void *inData,
	size_t inDataLength,
	void **outData,
	size_t *outDataLength)
{
	BUFFER_COMPRESS_INFO compressInfo;
	compressInfo.inData = inData;
	compressInfo.inDataLength = inDataLength;
	compressInfo.inDataPos = 0;
	compressInfo.outData = alloc_big(NULL,2*inDataLength);
	compressInfo.outDataLength = 2*inDataLength;
	compressInfo.outDataPos = 0;
	if (NULL == compressInfo.outData)
	{
		return SZ_ERROR_MEM;
	}
	int res = zzyLzmaDec_decode(&compressInfo,bufferRead,bufferWrite);
	if (SZ_OK == res)
	{
		*outData = compressInfo.outData;
		*outDataLength = compressInfo.outDataPos;
	}
	else
	{
		free_big(NULL,compressInfo.outData);
	}
	return res;
}

unsigned __int64 zzyLzma_getDecompressedLength(unsigned char header[9])
{
	unsigned __int64 unpackSize = 0;
	for (int i=0;i<8;++i)
		unpackSize += (UInt64)header[1 + i] << (i * 8);
	return unpackSize;
}
