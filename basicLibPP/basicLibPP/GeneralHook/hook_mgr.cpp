//////////////////////////////////////////////////////////////////////////
//
// Hook manager
// Author: zzy
//
//////////////////////////////////////////////////////////////////////////


#include <map>
#include <set>

using namespace std;

#include "hook_mgr.h"
#include "../HookLib/Hook.h"


//////////////////////////////////////////////////////////////////////////


static BLPP_QUEUED_LOCK HM_Lock = BLPP_QUEUED_LOCK_INIT;   // Lock for sync.
static PHOOK_CONTEXT HM_HookCtx = NULL;                    // Context of hook lib.


//////////////////////////////////////////////////////////////////////////


// Alloc & Check context.

static T_bool InternalAllocHookCtx()
{
    MEM_MANAGER mgr;
    mgr.alloc = tmpMemAlloc;
    mgr.free = tmpMemFree;
    mgr.userdata = NULL;
    HM_HookCtx = Hook_New(&mgr);
    if (NULL == HM_HookCtx)
    {
        return FALSE;
    }
    return TRUE;
}

inline static T_bool InternalSetCtxOK()
{
    if (NULL == HM_HookCtx)
    {
        if (!InternalAllocHookCtx())
        {
            return FALSE;
        }
    }
    return TRUE;
}


//////////////////////////////////////////////////////////////////////////


#define HM_IN LOCK_AcquireQueuedLockExclusive(&HM_Lock)
#define HM_OUT LOCK_ReleaseQueuedLockExclusive(&HM_Lock)
#define HM_OK InternalSetCtxOK()

#define MY_ALLOC(_s) blpp_mem_alloc(_s)
#define MY_FREE(_p) blpp_mem_free(_p)


//////////////////////////////////////////////////////////////////////////


static map<T_Dword,bool> HM_Thread;                        // Map to save thread id.


//////////////////////////////////////////////////////////////////////////


// Thread operation.

T_bool blpp_Hook_AddThread(T_Dword TID)
{
    T_bool bRet;
    HM_IN;
    if (!HM_OK)
    {
        bRet = FALSE;
        goto _ec;
    }
    bRet = HOOK_AddThread(HM_HookCtx,TID);
    if (bRet)
    {
        HM_Thread.insert(pair<T_Dword,bool>(TID,true));
    }
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_RemoveThread(T_Dword TID)
{
    T_bool bRet;
    HM_IN;
    if (!HM_OK)
    {
        bRet = FALSE;
        goto _ec;
    }
    bRet = HOOK_RemoveThread(HM_HookCtx,TID);
    if (bRet)
    {
        HM_Thread.erase(TID);
    }
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_RefreshThread()
{
    T_bool bRet;
    HM_IN;
    if (!HM_OK)
    {
        bRet = FALSE;
        goto _ec;
    }
    bRet = HOOK_SetAllThreadAlive(HM_HookCtx);
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_AddAllThread()
{
    T_bool bRet;
    HM_IN;
    if (!HM_OK)
    {
        bRet = FALSE;
        goto _ec;
    }
    // Mark all.
    for (map<T_Dword,bool>::iterator it=HM_Thread.begin();it!=HM_Thread.end();++it)
    {
        it->second = false;
    }
    // Enum.
    NTSTATUS status;
    PT_void buffer;
    ULONG bufferSize;
    bufferSize = 0x4000;
    buffer = blpp_mem_alloc(bufferSize);
    if (NULL == buffer)
    {
        bRet = FALSE;
        goto _ec;
    }
    while (true)
    {
        status = NtQuerySystemInformation(SystemProcessInformation,buffer,bufferSize,&bufferSize);
        if (STATUS_BUFFER_TOO_SMALL==status || STATUS_INFO_LENGTH_MISMATCH==status)
        {
            blpp_mem_free(buffer);
            bufferSize += 0x1000;
            buffer = blpp_mem_alloc(bufferSize);
            if (NULL == buffer)
            {
                bRet = FALSE;
                goto _ec;
            }
        }
        else
        {
            break;
        }
    }
    if (!NT_SUCCESS(status))
    {
        blpp_mem_free(buffer);
        bRet = FALSE;
        goto _ec;
    }
    PSYSTEM_PROCESS_INFORMATION pPS = (PSYSTEM_PROCESS_INFORMATION)buffer;
    T_Dword pid = GetCurrentProcessId();
    while (pPS)
    {
        if (pid == (T_Dword)pPS->UniqueProcessId)
        {
            for (size_t i=0;i<pPS->NumberOfThreads;++i)
            {
                T_Dword tid = (T_Dword)pPS->Threads[i].ClientId.UniqueThread;
                map<T_Dword,bool>::iterator it = HM_Thread.find(tid);
                if (it != HM_Thread.end())
                {
                    it->second = true;
                }
                else
                {
                    if (HOOK_AddThread(HM_HookCtx,tid))
                    {
                        HM_Thread.insert(pair<T_Dword,bool>(tid,true));
                    }
                }
            }
            break;
        }
        pPS = (pPS->NextEntryOffset?((PSYSTEM_PROCESS_INFORMATION)((T_address)(pPS)+(T_address)(pPS->NextEntryOffset))):NULL);
    }
    blpp_mem_free(buffer);
    // Now clean thread.
    for (map<T_Dword,bool>::iterator it=HM_Thread.begin();it!=HM_Thread.end();)
    {
        if (!it->second)
        {
            if (HOOK_RemoveThread(HM_HookCtx,it->first))
            {
                HM_Thread.erase(it++);
            }
            else
            {
                ++it;
            }
        }
        else
        {
            ++it;
        }
    }
    bRet = TRUE;
_ec:
    HM_OUT;
    return bRet;
}


//////////////////////////////////////////////////////////////////////////


// Main value.

#define HM_MAX_CODE_SIZE (128)

#if defined(_M_IX86)
    #include <PshPack4.h>
#elif defined(_M_X64)
    #include <PshPack8.h>
#else
    #error "not support."
#endif

typedef struct _HM_FILTER
{
    T_byte FixCode[HM_MAX_CODE_SIZE]; // Shell code must be aligned.
    PT_void Target;
    T_bool bWork;
    PT_void Cookie;
} HM_FILTER, *PHM_FILTER;

#include <PopPack.h>

static map<char*,PHM_FILTER> HM_BypassFilterMap;
static set<PT_void> HM_bypassCookies;
static set<PT_void> HM_directCookies;


//////////////////////////////////////////////////////////////////////////


// Main hook function.

static T_status InternalChangeBypassFilter(PHM_FILTER pFlt,__pfn_blpp_Hook_BypassCallBack pCallBack,PT_void Param,PT_void *pCookie)
{
#if defined(_M_IX86)
    *((PT_Bit32u)&pFlt->FixCode[6]) = (T_Bit32u)Param;
    InterlockedExchangePointer((PT_void *)&pFlt->FixCode[24],pCallBack);
#elif defined(_M_X64)
    *((PT_Bit64u)&pFlt->FixCode[36]) = (T_Bit64u)Param;
    InterlockedExchangePointer((PT_void *)&pFlt->FixCode[64],pCallBack);
#else
    #error "not support."
#endif
    if (pCookie)
    {
        *pCookie = pFlt;
    }
    return T_STATUS_SUCCESS;
}

T_status blpp_Hook_SetBypassFilter(PT_void Target,__pfn_blpp_Hook_BypassCallBack pCallBack,PT_void Param,PT_void *pCookie,T_bool bReplace)
{
    T_status Status = T_STATUS_UNKOWN_ERROR;
    map<char*,PHM_FILTER>::iterator it;
    if (NULL==Target || NULL==pCallBack)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    HM_IN;
    if (!HM_OK)
    {
        Status = T_STATUS_INSUFFICIENT_RESOURCES;
        goto _ec;
    }
    // Find if hooked.
    it = HM_BypassFilterMap.find((char*)Target);
    if (it != HM_BypassFilterMap.end())
    {
        if (bReplace)
        {
            Status = InternalChangeBypassFilter(it->second,pCallBack,Param,pCookie);
        }
        else
        {
            Status = T_STATUS_ALREADY_EXISTS;
        }
        goto _ec;
    }
    PHM_FILTER pFlt = (PHM_FILTER)MY_ALLOC(sizeof(HM_FILTER));
    if (NULL == pFlt)
    {
        Status = T_STATUS_INSUFFICIENT_RESOURCES;
        goto _ec;
    }
    pFlt->Target = Target;
    pFlt->bWork = FALSE;
    PT_void JumpBack = NULL;
    HOOK_STATUS hStatus = Hook_DetourAttach(HM_HookCtx,Target,pFlt->FixCode,&pFlt->Cookie,&JumpBack);
    if (HOOK_STATUS_SUCCESS != hStatus)
    {
        MY_FREE(pFlt);
        switch (hStatus)
        {
        case HOOK_STATUS_ALREADY_HOOKED:
            Status = T_STATUS_ALREADY_EXISTS;
            break;
        case HOOK_STATUS_INSUFFICIENT_MEMORY:
            Status = T_STATUS_INSUFFICIENT_RESOURCES;
            break;
        default:
            Status = T_STATUS_ACCESS_DENIED;
            break;
        }
        goto _ec;
    }
    //
    // Now write core code.
    //
#if defined(_M_IX86)
    T_byte FixCode[] = 
    {
        /* 00 */ 0x60,0x9C,                                          // pushad; pushfd;
        /* 02 */ 0x89,0xE0,                                          // mov eax,esp;               <-- Info, esp
        /* 04 */ 0x50,                                               // push eax;                  <-- Info
        /* 05 */ 0xB8,0x88,0x88,0x88,0x88,                           // mov eax,0x88888888;        <-- Set param
        /* 10 */ 0x50,                                               // push eax;                  <-- Param
        /* 11 */ 0xB8,0x88,0x88,0x88,0x88,                           // mov eax,0x88888888;        <-- Set ret addr
        /* 16 */ 0x50,                                               // push eax;                  <-- ret addr
        /* 17 */ 0x90,                                               // nop;
        /* 18 */ 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  // jmp dword [0x0]; dd 0;     <-- dd 0 must be aligned 4.
        /* 28 */ 0x58,0x61,                                          // pop eax; popad;            <-- ignore eflag.
        /* 30 */ 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  // jmp dword [0x0]; dd 0;     <-- dd 0 must be aligned 4.
    };
    T_Dword FixCodeLength = sizeof(FixCode);
    *((PT_Bit32u)&FixCode[ 6]) = (T_Bit32u)Param;
    *((PT_Bit32u)&FixCode[12]) = (T_Bit32u)pFlt->FixCode+28;
    *((PT_Bit32u)&FixCode[20]) = (T_Bit32u)pFlt->FixCode+24;
    *((PT_Bit32u)&FixCode[24]) = (T_Bit32u)pCallBack;
    *((PT_Bit32u)&FixCode[32]) = (T_Bit32u)pFlt->FixCode+36;
    *((PT_Bit32u)&FixCode[36]) = (T_Bit32u)JumpBack;
#elif defined(_M_X64)
    T_byte FixCode[] = 
    {
/*
        00000000  50                push rax
        00000001  51                push rcx
        00000002  52                push rdx
        00000003  53                push rbx
        00000004  4889E0            mov rax,rsp
        00000007  480520000000      add rax,0x20
        0000000D  50                push rax
        0000000E  55                push rbp
        0000000F  56                push rsi
        00000010  57                push rdi
        00000011  4150              push r8
        00000013  4151              push r9
        00000015  4152              push r10
        00000017  4153              push r11
        00000019  4154              push r12
        0000001B  4155              push r13
        0000001D  4156              push r14
        0000001F  4157              push r15
        00000021  9C                pushfq
*/
        /* 000 */ 0x50,0x51,0x52,0x53,0x48,0x89,0xE0,0x48,0x05,0x20,0x00,0x00,0x00,0x50,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x9C,
/*
        00000022  48B9777777778888  mov rcx,0x8888888877777777
                  -8888
        0000002C  4889E2            mov rdx,rsp
        0000002F  48B8777777778888  mov rax,0x8888888877777777
                  -8888
        00000039  50                push rax
*/
        /* 034 */ 0x48,0xB9,0x77,0x77,0x77,0x77,0x88,0x88,0x88,0x88,
        /* 044 */ 0x48,0x89,0xE2,
        /* 047 */ 0x48,0xB8,0x77,0x77,0x77,0x77,0x88,0x88,0x88,0x88,
        /* 057 */ 0x50,
        /* 058 */ 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    // <-- jmp dd 0 must be aligned 8.
/*
        0000003B  58                pop rax        <-- ignore rflag
        0000003C  415F              pop r15
        0000003E  415E              pop r14
        00000040  415D              pop r13
        00000042  415C              pop r12
        00000044  415B              pop r11
        00000046  415A              pop r10
        00000048  4159              pop r9
        0000004A  4158              pop r8
        0000004C  5F                pop rdi
        0000004D  5E                pop rsi
        0000004E  5D                pop rbp
        0000004F  58                pop rax        <-- ignore rsp
        00000050  5B                pop rbx
        00000051  5A                pop rdx
        00000052  59                pop rcx
        00000053  58                pop rax
*/
        /* 072 */ 0xCC,
        /* 073 */ 0x58,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x58,0x5B,0x5A,0x59,0x58,
        /* 098 */ 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00     // <-- jmp dd 0 must be aligned 8.
    };
    T_Dword FixCodeLength = sizeof(FixCode);
    *((PT_Bit64u)&FixCode[ 36]) = (T_Bit64u)Param;
    *((PT_Bit64u)&FixCode[ 49]) = (T_Bit64u)pFlt->FixCode+73;
    *((PT_Bit64u)&FixCode[ 64]) = (T_Bit64u)pCallBack;
    *((PT_Bit64u)&FixCode[104]) = (T_Bit64u)JumpBack;
#else
    #error "not support."
#endif
    // Copy shellcode;
    memcpy(pFlt->FixCode,FixCode,FixCodeLength);
    // OK;
    HM_BypassFilterMap.insert(pair<char*,PHM_FILTER>((char*)Target,pFlt));
	HM_bypassCookies.insert(pFlt);
    if (pCookie)
    {
        *pCookie = pFlt;
    }
    Status = T_STATUS_SUCCESS;
_ec:
    HM_OUT;
    return Status;
}

T_bool blpp_Hook_RemoveBypassFilter(PT_void Cookie)
{
    PHM_FILTER pFlt = (PHM_FILTER)Cookie;
    T_bool bRet = FALSE;
    HM_IN;
    // if cookie is ok,HM is ok.
	if (HM_bypassCookies.find(pFlt) == HM_bypassCookies.end())
	{
		goto _ec;
	}
    // Ok,got it.
    if (pFlt->bWork)
    {
        Hook_StopFilter(HM_HookCtx,pFlt->Cookie);
    }
    if (HOOK_STATUS_SUCCESS == Hook_DetourDetach(HM_HookCtx,pFlt->Cookie))
    {
        HM_BypassFilterMap.erase((char*)pFlt->Target);
		HM_bypassCookies.erase(pFlt);
        MY_FREE(pFlt);
        bRet = TRUE;
    }
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_StartBypassFilter(PT_void Cookie)
{
	PHM_FILTER pFlt = (PHM_FILTER)Cookie;
    T_bool bRet = FALSE;
    HM_IN;
    // if cookie is ok,HM is ok.
	if (HM_bypassCookies.find(pFlt) == HM_bypassCookies.end())
	{
		goto _ec;
	}
    if (pFlt->bWork)
    {
        bRet = TRUE;
    }
    else
    {
        bRet = Hook_StartFilter(HM_HookCtx,pFlt->Cookie);
        pFlt->bWork = bRet;
    }
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_StopBypassFilter(PT_void Cookie)
{
	PHM_FILTER pFlt = (PHM_FILTER)Cookie;
    T_bool bRet = FALSE;
    HM_IN;
    // if cookie is ok,HM is ok.
	if (HM_bypassCookies.find(pFlt) == HM_bypassCookies.end())
	{
		goto _ec;
	}
    if (pFlt->bWork)
    {
        bRet = Hook_StopFilter(HM_HookCtx,pFlt->Cookie);
        if (bRet)
        {
            pFlt->bWork = FALSE;
        }
    }
    else
    {
        bRet = TRUE;
    }
_ec:
    HM_OUT;
    return bRet;
}

T_status blpp_Hook_SetDirectFilter(PT_void Target,PT_void Filter,PT_void *JumpBack,PT_void *pCookie)
{
    T_status Status = T_STATUS_UNKOWN_ERROR;
    if (NULL==Target || NULL==Filter || NULL==JumpBack)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    HM_IN;
    if (!HM_OK)
    {
        Status = T_STATUS_INSUFFICIENT_RESOURCES;
        goto _ec;
    }
    PT_void Cookie;
    HOOK_STATUS hStatus = Hook_DetourAttach(HM_HookCtx,Target,Filter,&Cookie,JumpBack);
    if (HOOK_STATUS_SUCCESS != hStatus)
    {
        switch (hStatus)
        {
        case HOOK_STATUS_ALREADY_HOOKED:
            Status = T_STATUS_ALREADY_EXISTS;
            break;
        case HOOK_STATUS_INSUFFICIENT_MEMORY:
            Status = T_STATUS_INSUFFICIENT_RESOURCES;
            break;
        default:
            Status = T_STATUS_ACCESS_DENIED;
            break;
        }
        goto _ec;
    }
	HM_directCookies.insert(Cookie);
    if (pCookie)
    {
        *pCookie = Cookie;
    }
    Status = T_STATUS_SUCCESS;
_ec:
    HM_OUT;
    return Status;
}

T_bool blpp_Hook_RemoveDirectFilter(PT_void Cookie)
{
    T_bool bRet = FALSE;
    HM_IN;
    if (!HM_OK)
    {
        goto _ec;
    }
	if (HM_directCookies.find(Cookie) == HM_directCookies.end())
	{
		goto _ec;
	}
    bRet = (HOOK_STATUS_SUCCESS==Hook_DetourDetach(HM_HookCtx,Cookie));
	if (bRet)
	{
		HM_directCookies.erase(Cookie);
	}
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_StartDirectFilter(PT_void Cookie)
{
    T_bool bRet = FALSE;
    HM_IN;
    if (!HM_OK)
    {
        goto _ec;
    }
	if (HM_directCookies.find(Cookie) == HM_directCookies.end())
	{
		goto _ec;
	}
    bRet = Hook_StartFilter(HM_HookCtx,Cookie);
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_StopDirectFilter(PT_void Cookie)
{
    T_bool bRet = FALSE;
    HM_IN;
    if (!HM_OK)
    {
        goto _ec;
    }
	if (HM_directCookies.find(Cookie) == HM_directCookies.end())
	{
		goto _ec;
	}
    bRet = Hook_StopFilter(HM_HookCtx,Cookie);
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_FixHook(PT_Dword pCount)
{
    T_bool bRet = FALSE;
    HM_IN;
    if (!HM_OK)
    {
        goto _ec;
    }
    bRet = Hook_FixDetour(HM_HookCtx,pCount);
_ec:
    HM_OUT;
    return bRet;
}

T_bool blpp_Hook_IsHookContext(PT_void Ptr,T_address Length)
{
    T_bool bRet = FALSE;
    HM_IN;
    if (!HM_OK)
    {
		goto _ec;
    }
    bRet = Hook_IsDetourContextMemory(HM_HookCtx,Ptr,Length);
_ec:
    HM_OUT;
    return bRet;
}

PT_void blpp_Hook_AllocSmartCallBackCode(PT_void Param,__pfn_blpp_Hook_SmartCallBack pCallBack,PT_void JumpBack)
{
    PT_void pCode = NULL;
#if defined(_M_IX86)
    T_byte ShellCode[] = 
    {
        /* 00 */ 0x50,                                               // push eax;
        /* 01 */ 0xB8,0x88,0x88,0x88,0x88,                           // mov eax,0x88888888;
        /* 06 */ 0x50,                                               // push eax;
        /* 07 */ 0xB8,0x88,0x88,0x88,0x88,                           // mov eax,0x88888888;
        /* 12 */ 0x50,                                               // push eax;
        /* 13 */ 0xFF,0x25,0x00,0x00,0x00,0x00,0xCC,0x00,0x00,0x00,0x00 // jmp dword [0x0]; dd 0;     <-- dd 0 must be aligned 4.
    };
    T_Dword ShellCodeLength = sizeof(ShellCode);
    pCode = MY_ALLOC(ShellCodeLength);
    if (NULL == pCode)
    {
        return NULL;
    }
    *((PT_Bit32u)&ShellCode[ 2]) = (T_Bit32u)Param;
    *((PT_Bit32u)&ShellCode[ 8]) = (T_Bit32u)JumpBack;
    *((PT_Bit32u)&ShellCode[15]) = (T_Bit32u)pCode + 20;
    *((PT_Bit32u)&ShellCode[20]) = (T_Bit32u)pCallBack;
#elif defined(_M_X64)
    T_byte ShellCode[] = 
    {
        /* 00 */ 0x48,0xB9,0x77,0x77,0x77,0x77,0x88,0x88,0x88,0x88,  // mov rcx,??
        /* 10 */ 0x48,0x89,0xC2,                                     // mov rdx,rax
        /* 13 */ 0x48,0xB8,0x77,0x77,0x77,0x77,0x88,0x88,0x88,0x88,  // mov rax,??
        /* 23 */ 0x50,                                               // push rax;
        /* 24 */ 0xFF,0x25,0x02,0x00,0x00,0x00,0xCC,0xCC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 // <-- jmp dd 0 must be aligned 8.
    };
    T_Dword ShellCodeLength = sizeof(ShellCode);
    pCode = MY_ALLOC(ShellCodeLength);
    if (NULL == pCode)
    {
        return NULL;
    }
    *((PT_Bit64u)&ShellCode[ 2]) = (T_Bit64u)Param;
    *((PT_Bit64u)&ShellCode[15]) = (T_Bit64u)JumpBack;
    *((PT_Bit64u)&ShellCode[32]) = (T_Bit64u)pCallBack;
#else
    #error "not support."
#endif
    memcpy(pCode,ShellCode,ShellCodeLength);
    return pCode;
}

T_void blpp_Hook_FreeSmartCallBackCode(PT_void pCode)
{
    MY_FREE(pCode);
}
