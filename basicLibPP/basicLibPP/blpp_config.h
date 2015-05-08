//////////////////////////////////////////////////////////////////////////
//
// Config
//
// Author: ZZY
//
//////////////////////////////////////////////////////////////////////////


#pragma once

#include "blpp_typedef.h"
#include <Windows.h>


//////////////////////////////////////////////////////////////////////////


//
// Platform setting
//

// Debug
#define Config_DBG 0

#ifndef NDEBUG
	#define NDEBUG
#endif

// CPU
#if defined(_M_IX86)
#elif defined(_M_X64)
#else
    #error "You must define the machine type."
#endif

#define Config_Little_Endian 1

// File system
#define Config_MAX_PATH 260


#if Config_Little_Endian
    typedef union _T_LargeInteger
    {
	    struct
	    {
		    T_Bit32u LowPart;
		    T_Bit32s HighPart;
	    } s;
	    T_Bit64s QuadPart_s;
	    struct
	    {
		    T_Bit32u LowPart;
		    T_Bit32u  HighPart;
	    } u;
	    T_Bit64u QuadPart_u;
    } T_LargeInteger, *PT_LargeInteger;
#else
    typedef union _T_LargeInteger
    {
	    struct
	    {
		    T_Bit32s HighPart;
		    T_Bit32u LowPart;
	    } s;
	    T_Bit64s QuadPart_s;
	    struct
	    {
		    T_Bit32u  HighPart;
		    T_Bit32u LowPart;
	    } u;
	    T_Bit64u QuadPart_u;
    } T_LargeInteger, *PT_LargeInteger;
#endif

//
// Define a special type of WORD / DWORD,so that we can recognize it correctly on different CPU types.
//
typedef struct _T_StandardWord
{
	T_byte atom[2];
} T_StandardWord, *PT_StandardWord;

typedef struct _T_StandardDword
{
	T_byte Datom[4];
} T_StandardDword, *PT_StandardDword;

// Special functions for it.
#define T_Word_to_StandardWord(_Ptr,_Word) {(_Ptr)->atom[0] = (T_byte)((_Word) & 0xFF);(_Ptr)->atom[1] = (T_byte)(((_Word) >> 8) & 0xFF);}
#define T_StandardWord_to_Word(_Ptr) (((T_Word)((_Ptr)->atom[0])) | (((T_Word)((_Ptr)->atom[1])) << 8))

#define T_Dword_to_StandardDword(_Ptr,_Dword) {(_Ptr)->Datom[0] = (T_byte)((_Dword) & 0xFF);(_Ptr)->Datom[1] = (T_byte)(((_Dword) >> 8) & 0xFF);(_Ptr)->Datom[2] = (T_byte)(((_Dword) >> 16) & 0xFF);(_Ptr)->Datom[3] = (T_byte)(((_Dword) >> 24) & 0xFF);}
#define T_StandardDword_to_Dword(_Ptr) (((T_Dword)((_Ptr)->Datom[0])) | (((T_Dword)((_Ptr)->Datom[1])) << 8) | (((T_Dword)((_Ptr)->Datom[2])) << 16) | (((T_Dword)((_Ptr)->Datom[3])) << 24))


//
// Double link list entry.
//
typedef struct _T_ListEntry
{
    _T_ListEntry *pPrev;
    _T_ListEntry *pNext;
} T_ListEntry, *PT_ListEntry;

inline void T_ListEntry_InitListHead(PT_ListEntry pListHead)
{
    pListHead->pNext = pListHead->pPrev = pListHead;
}

inline void T_ListEntry_InsertHeadList(PT_ListEntry pListHead,PT_ListEntry pEntry)
{
    pEntry->pNext = pListHead->pNext;
    pEntry->pPrev = pListHead;
    pListHead->pNext = pEntry; // pEntry->pPrev->pNext = pEntry;
    pEntry->pNext->pPrev = pEntry;
}

inline void T_ListEntry_InsertTailList(PT_ListEntry pListHead,PT_ListEntry pEntry)
{
    pEntry->pNext = pListHead;
    pEntry->pPrev = pListHead->pPrev;
    pEntry->pPrev->pNext = pEntry;
    pListHead->pPrev = pEntry; // pEntry->pNext->pPrev = pEntry;
}

inline T_bool T_ListEntry_IsListEmpty(PT_ListEntry pListHead)
{
    return (pListHead == pListHead->pNext);
}

inline void T_ListEntry_RemoveEntryList(PT_ListEntry pEntry)
{
    pEntry->pPrev->pNext = pEntry->pNext;
    pEntry->pNext->pPrev = pEntry->pPrev;
}

inline PT_ListEntry T_ListEntry_RemoveHeadList(PT_ListEntry pListHead)
{
    PT_ListEntry pEntry;
    pEntry = pListHead->pNext;
    if (pListHead == pEntry)
    {
        return NULL;
    }
    pListHead->pNext = pEntry->pNext; // pEntry->pPrev->pNext = pEntry->pNext;
    pEntry->pNext->pPrev = pListHead; // pEntry->pNext->pPrev = pEntry->pPrev;
    return pEntry;
}

inline PT_ListEntry T_ListEntry_RemoveTailList(PT_ListEntry pListHead)
{
    PT_ListEntry pEntry;
    pEntry = pListHead->pPrev;
    if (pListHead == pEntry)
    {
        return NULL;
    }
    pEntry->pPrev->pNext = pListHead; // pEntry->pPrev->pNext = pEntry->pNext;
    pListHead->pPrev = pEntry->pPrev; // pEntry->pNext->pPrev = pEntry->pPrev;
    return pEntry;
}
