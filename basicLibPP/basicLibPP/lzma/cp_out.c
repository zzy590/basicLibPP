
#include "LzmaEnc.h"
#include "LzmaDec.h"
#include "cp_out.h"

#define LZMA_PROPS_SIZE 5

int
zzyCpEng_Compress
(
  void *lParam,
  unsigned char *dest,
  size_t *destLen,
  const unsigned char *src,
  size_t srcLen,
  int level, /* 0 <= level <= 9, default = 5 */
  unsigned dictSize, /* use (1 << N) or (3 << N). 4 KB < dictSize <= 128 MB */
  int lc, /* 0 <= lc <= 8, default = 3  */
  int lp, /* 0 <= lp <= 4, default = 0  */
  int pb, /* 0 <= pb <= 4, default = 2  */
  int fb,  /* 5 <= fb <= 273, default = 32 */
  __pfn_MemAlloc pAlloc,
  __pfn_MemFree pFree
)
{
  int i;
  __int64 allsize;
  ISzAlloc g_Alloc;
  size_t HeaderSize,propsSize;
  CLzmaEncProps props;
  //
  // Init vaule.
  //
  g_Alloc.Alloc = pAlloc;
  g_Alloc.Free = pFree;
  g_Alloc.lParam = lParam;
  HeaderSize = propsSize = LZMA_PROPS_SIZE;
  allsize = srcLen;
  //
  // Set props.
  //
  LzmaEncProps_Init(&props);
  props.level = level;
  props.dictSize = dictSize;
  props.lc = lc;
  props.lp = lp;
  props.pb = pb;
  props.fb = fb;
  props.numThreads = 1;
  //
  // Set header.
  //
  for (i = 0; i < 8; i++)
  {
    dest[HeaderSize++] = (Byte)(allsize >> (8 * i));
  }
  //
  // Compress.
  //
  *destLen -= HeaderSize;
  i = LzmaEncode(dest + HeaderSize,destLen,src,srcLen,&props,dest,&propsSize,0,NULL,&g_Alloc,&g_Alloc);
  *destLen += HeaderSize;
  return i;
}

__int64
zzyCpEng_GetUncompressedSize
(
  unsigned char header[13]
)
{
  int i;
  __int64 unpackSize;
  unpackSize = 0;
  for (i = 0; i < 8; i++)
  {
    unpackSize += (UInt64)header[LZMA_PROPS_SIZE + i] << (i * 8);
  }
  return unpackSize;
}

int
zzyCpEng_Uncompress
(
  void *lParam,
  unsigned char *dest,
  size_t *destLen,
  const unsigned char *src,
  size_t *srcLen,
  __pfn_MemAlloc pAlloc,
  __pfn_MemFree pFree
)
{
  ELzmaStatus status;
  int ret;
  ISzAlloc g_Alloc;
  //
  // Init value.
  //
  g_Alloc.Alloc = pAlloc;
  g_Alloc.Free = pFree;
  g_Alloc.lParam = lParam;
  if ((__int64)*destLen < zzyCpEng_GetUncompressedSize((unsigned char *)src))
  {
      return SZ_ERROR_OUTPUT_EOF;
  }
  *srcLen -= (LZMA_PROPS_SIZE + 8);
  ret = LzmaDecode(dest,destLen,src + LZMA_PROPS_SIZE + 8,srcLen,src,LZMA_PROPS_SIZE,LZMA_FINISH_ANY,&status,&g_Alloc);
  *srcLen += (LZMA_PROPS_SIZE + 8);
  return ret;
}

int
zzyCpEng_StreamCompress
(
  void *lParam,
  __int64 AllInSize,
  __pfn_Read pIn,
  __pfn_Write pOut,
  int level, /* 0 <= level <= 9, default = 5 */
  unsigned dictSize, /* use (1 << N) or (3 << N). 4 KB < dictSize <= 128 MB */
  int lc, /* 0 <= lc <= 8, default = 3  */
  int lp, /* 0 <= lp <= 4, default = 0  */
  int pb, /* 0 <= pb <= 4, default = 2  */
  int fb,  /* 5 <= fb <= 273, default = 32 */
  __pfn_MemAlloc pAlloc,
  __pfn_MemFree pFree
)
{
  CLzmaEncHandle enc;
  SRes res;
  CLzmaEncProps props;
  ISzAlloc g_Alloc;
  ISeqInStream InStream;
  ISeqOutStream OutStream;
  //
  // Init value.
  //
  g_Alloc.Alloc = pAlloc;
  g_Alloc.Free = pFree;
  g_Alloc.lParam = lParam;
  InStream.Read = pIn;
  InStream.lParam = lParam;
  OutStream.Write = pOut;
  OutStream.lParam = lParam;
  //
  // Start.
  //
  enc = LzmaEnc_Create(&g_Alloc);
  if (enc == 0)
  {
    return SZ_ERROR_MEM;
  }
  LzmaEncProps_Init(&props);
  props.level = level;
  props.dictSize = dictSize;
  props.lc = lc;
  props.lp = lp;
  props.pb = pb;
  props.fb = fb;
  props.numThreads = 1;
  res = LzmaEnc_SetProps(enc, &props);
  if (SZ_OK == res)
  {
    Byte header[LZMA_PROPS_SIZE + 8];
    size_t headerSize = LZMA_PROPS_SIZE;
    int i;
    res = LzmaEnc_WriteProperties(enc, header, &headerSize);
    for (i = 0; i < 8; i++)
    {
      header[headerSize++] = (Byte)(AllInSize >> (8 * i));
    }
    if (SZ_OK == res)
    {
      if (pOut(lParam, header, headerSize) != headerSize)
      {
        res = SZ_ERROR_WRITE;
      }
      else
      {
        res = LzmaEnc_Encode(enc, &OutStream, &InStream, NULL, &g_Alloc, &g_Alloc);
      }
    }
  }
  LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
  return res;
}

#define _BUF_SIZE (1 << 18)

SRes
Decode2
(
  CLzmaDec *state,
  ISeqOutStream *outStream,
  ISeqInStream *inStream,
  UInt64 unpackSize,
  ISzAlloc *g_Alloc
)
{
  int thereIsSize = (unpackSize != (UInt64)(Int64)-1);
  Byte *pBuf;
  Byte *inBuf;
  Byte *outBuf;
  size_t inPos = 0, inSize = 0, outPos = 0;
  SRes res;
  SizeT inProcessed;
  SizeT outProcessed;
  ELzmaFinishMode finishMode;
  ELzmaStatus status;
  //
  // Alloc memory.
  //
  pBuf = g_Alloc->Alloc(g_Alloc->lParam,_BUF_SIZE * 2);
  if (!pBuf)
  {
      return SZ_ERROR_MEM;
  }
  inBuf = pBuf;
  outBuf = pBuf + _BUF_SIZE;
  LzmaDec_Init(state);
  for (;;)
  {
    if (inPos == inSize)
    {
      inSize = _BUF_SIZE;
      if (SZ_OK != inStream->Read(inStream->lParam, inBuf, &inSize))
      {
        g_Alloc->Free(g_Alloc->lParam,pBuf);
        return SZ_ERROR_READ;
      }
      inPos = 0;
    }
    inProcessed = inSize - inPos;
    outProcessed = _BUF_SIZE - outPos;
    finishMode = LZMA_FINISH_ANY;
    if (thereIsSize && outProcessed > unpackSize)
    {
      outProcessed = (SizeT)unpackSize;
      finishMode = LZMA_FINISH_END;
    }
    res = LzmaDec_DecodeToBuf(state, outBuf + outPos, &outProcessed,
      inBuf + inPos, &inProcessed, finishMode, &status);
    inPos += inProcessed;
    outPos += outProcessed;
    unpackSize -= outProcessed;
    if (outStream)
    {
      if (outStream->Write(outStream->lParam, outBuf, outPos) != outPos)
      {
        g_Alloc->Free(g_Alloc->lParam,pBuf);
        return SZ_ERROR_WRITE;
      }
    }
    outPos = 0;
    if (res != SZ_OK || thereIsSize && unpackSize == 0)
    {
      g_Alloc->Free(g_Alloc->lParam,pBuf);
      return res;
    }
    if (inProcessed == 0 && outProcessed == 0)
    {
      if (thereIsSize || status != LZMA_STATUS_FINISHED_WITH_MARK)
      {
        res = SZ_ERROR_DATA;
      }
      g_Alloc->Free(g_Alloc->lParam,pBuf);
      return res;
    }
  }
}

int
zzyCpEng_StreamUncompress
(
  void *lParam,
  __pfn_Read pIn,
  __pfn_Write pOut,
  __pfn_MemAlloc pAlloc,
  __pfn_MemFree pFree
)
{
  UInt64 unpackSize;
  int i;
  size_t transSize;
  SRes res = 0;
  CLzmaDec state;
  /* header: 5 bytes of LZMA properties and 8 bytes of uncompressed size */
  unsigned char header[LZMA_PROPS_SIZE + 8];
  ISzAlloc g_Alloc;
  ISeqInStream InStream;
  ISeqOutStream OutStream;
  //
  // Init value.
  //
  g_Alloc.Alloc = pAlloc;
  g_Alloc.Free = pFree;
  g_Alloc.lParam = lParam;
  InStream.Read = pIn;
  InStream.lParam = lParam;
  OutStream.Write = pOut;
  OutStream.lParam = lParam;
  /* Read and parse header */
  transSize = sizeof(header);
  pIn(lParam,header,&transSize);
  if (sizeof(header) == transSize)
  {
    unpackSize = 0;
    for (i = 0; i < 8; i++)
    {
      unpackSize += (UInt64)header[LZMA_PROPS_SIZE + i] << (i * 8);
    }
    LzmaDec_Construct(&state);
    res = LzmaDec_Allocate(&state, header, LZMA_PROPS_SIZE, &g_Alloc);
    if (SZ_OK == res)
    {
      res = Decode2(&state, &OutStream, &InStream, unpackSize, &g_Alloc);
      LzmaDec_Free(&state, &g_Alloc);
    }
  }
  else
  {
      res = SZ_ERROR_INPUT_EOF;
  }
  return res;
}
