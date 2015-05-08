/************************************************************************/
/* Mini hook library                                                    */
/************************************************************************/

#include <Windows.h>
#include "Hook.h"

#include "../DisEng/dis_out.h"

/************************************************************************/

#define HOOK_MAX_JUMP_CODE_SIZE (16)
#define HOOK_MAX_FIX_CODE_SIZE (32)
#define HOOK_MAX_SHELL_CODE_SIZE (64)

#if defined(_M_IX86)
    #include <PshPack4.h>
#elif defined(_M_X64)
    #include <PshPack8.h>
#else
    #error "not support."
#endif

typedef struct _DETOUR_TRAMPOLINE
{
    T_byte rbCode[HOOK_MAX_JUMP_CODE_SIZE];
    _DETOUR_TRAMPOLINE *pbRemain;
} DETOUR_TRAMPOLINE, *PDETOUR_TRAMPOLINE;

#define DETOUR_TRAMPOLINE_USED ((PDETOUR_TRAMPOLINE)-1)

#if defined(_M_IX86)
    C_ASSERT(sizeof(DETOUR_TRAMPOLINE)%4 == 0);
#elif defined(_M_X64)
    C_ASSERT(sizeof(DETOUR_TRAMPOLINE)%8 == 0);
#else
    #error "not support."
#endif

typedef struct _DETOUR_REGION
{
    T_Dword             dwSignature;
    _DETOUR_REGION *    pNext;                             // Next region in list of regions.
    DETOUR_TRAMPOLINE * pFree;                             // List of free trampolines in this region.
} DETOUR_REGION, *PDETOUR_REGION;

#if defined(_M_IX86)
    C_ASSERT(sizeof(DETOUR_REGION)%4 == 0);
#elif defined(_M_X64)
    C_ASSERT(sizeof(DETOUR_REGION)%8 == 0);
#else
    #error "not support."
#endif

typedef struct _HOOK_DETOUR
{
    _HOOK_DETOUR *pNext;                                   // List of detours
    _HOOK_DETOUR *pSelf;                                   // Self point to check cookie
    PT_void To;                                            // User filter
    PT_void Target;                                        // Hooked point
    PT_void OriginalTarget;                                // The original target,Target will refresh when DisEng find short jump.
    PDETOUR_TRAMPOLINE pTrampoline;                        // Second jump to user filter
    PT_void HookFunction;                                  // Valued if point have old hook
    T_Dword FixLength;                                     // Length of patched code
    T_byte OriginalCode[HOOK_MAX_FIX_CODE_SIZE];           // Original code of hooked point
    T_byte FixCode[HOOK_MAX_FIX_CODE_SIZE];                // Changed code at hooked point
    T_byte ShellCode[HOOK_MAX_SHELL_CODE_SIZE];            // Shell code to jump to original code + patched length
} HOOK_DETOUR, *PHOOK_DETOUR;

#include <PopPack.h>

typedef struct _HOOK_THREAD_INFO
{
    _HOOK_THREAD_INFO *pNext;
    T_Dword TID;
    HANDLE hThread;
    T_bool Suspended;
} HOOK_THREAD_INFO, *PHOOK_THREAD_INFO;

typedef struct _HOOK_CONTEXT
{
    MEM_MANAGER mem_mgr;
    PDETOUR_REGION s_pRegions;                             // List of all regions.
    PDETOUR_REGION s_pRegion;                              // Default region.
    PHOOK_DETOUR HookList;
    PHOOK_THREAD_INFO ThreadList;
} HOOK_CONTEXT, *PHOOK_CONTEXT;

typedef enum _HOOK_TODO
{
    TO_HOOK = 0,
    TO_UNHOOK,
    TO_FIX,
} HOOK_TODO;

/************************************************************************/

static const T_Dword DETOUR_REGION_SIGNATURE = 'Dyzz';
static const T_Dword DETOUR_REGION_SIZE = 0x10000; // 64KB
static const T_Dword DETOUR_TRAMPOLINES_PER_REGION = ((DETOUR_REGION_SIZE - sizeof(DETOUR_REGION)) / sizeof(DETOUR_TRAMPOLINE));

/************************************************************************/
/* By Microsoft Detours.                                                */
/************************************************************************/

static void detour_writable_trampoline_regions(PHOOK_CONTEXT pCtx)
{
    // Mark all of the regions as writable.
    for (PDETOUR_REGION pRegion=pCtx->s_pRegions;pRegion!=NULL;pRegion=pRegion->pNext)
    {
        DWORD dwOld;
        VirtualProtect(pRegion,DETOUR_REGION_SIZE,PAGE_EXECUTE_READWRITE,&dwOld);
    }
}

static void detour_runnable_trampoline_regions(PHOOK_CONTEXT pCtx)
{
    HANDLE hProcess = GetCurrentProcess();
    // Mark all of the regions as executable.
    for (PDETOUR_REGION pRegion=pCtx->s_pRegions;pRegion!=NULL;pRegion=pRegion->pNext)
    {
        DWORD dwOld;
        VirtualProtect(pRegion,DETOUR_REGION_SIZE,PAGE_EXECUTE_READ,&dwOld);
        FlushInstructionCache(hProcess,pRegion,DETOUR_REGION_SIZE);
    }
}

static PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID detour_alloc_region_from_lo(PBYTE pbLo,PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);
    for (;pbTry < pbHi;)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (pbTry >= (PBYTE)(ULONG_PTR)0x50000000 &&
            pbTry <= (PBYTE)(ULONG_PTR)0x80000000)
        {
            // Skip region reserved for system DLLs.
            pbTry = (PBYTE)(ULONG_PTR)(0x80000000 + DETOUR_REGION_SIZE);
            continue;
        }
        ZeroMemory(&mbi,sizeof(mbi));
        if (!VirtualQuery(pbTry,&mbi,sizeof(mbi)))
        {
            break;
        }
        if ((MEM_FREE==mbi.State) && (mbi.RegionSize>=DETOUR_REGION_SIZE))
        {
            PVOID pv = VirtualAlloc(pbTry,DETOUR_REGION_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
            if (pv != NULL)
            {
                return pv;
            }
            pbTry += DETOUR_REGION_SIZE;
        }
        else
        {
            pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID detour_alloc_region_from_hi(PBYTE pbLo,PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);
    for (;pbTry > pbLo;)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (pbTry >= (PBYTE)(ULONG_PTR)0x50000000 &&
            pbTry <= (PBYTE)(ULONG_PTR)0x80000000)
        {
            // Skip region reserved for system DLLs.
            pbTry = (PBYTE)(ULONG_PTR)(0x50000000 - DETOUR_REGION_SIZE);
            continue;
        }
        ZeroMemory(&mbi,sizeof(mbi));
        if (!VirtualQuery(pbTry,&mbi,sizeof(mbi)))
        {
            break;
        }
        if ((MEM_FREE==mbi.State) && (mbi.RegionSize>=DETOUR_REGION_SIZE))
        {
            PVOID pv = VirtualAlloc(pbTry,DETOUR_REGION_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
            if (pv != NULL)
            {
                return pv;
            }
            pbTry -= DETOUR_REGION_SIZE;
        }
        else
        {
            pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase - DETOUR_REGION_SIZE);
        }
    }
    return NULL;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PHOOK_CONTEXT pCtx,PBYTE pbTarget)
{
    //
    // We have to place trampolines within +/- 2GB of target.
    //
    PDETOUR_TRAMPOLINE pLo = (PDETOUR_TRAMPOLINE)((pbTarget > (PBYTE)0x7ff80000) ? pbTarget - 0x7ff80000 : (PBYTE)(ULONG_PTR)DETOUR_REGION_SIZE);
    PDETOUR_TRAMPOLINE pHi = (PDETOUR_TRAMPOLINE)((pbTarget < (PBYTE)0xffffffff80000000) ? pbTarget + 0x7ff80000 : (PBYTE)0xfffffffffff80000);
    PDETOUR_TRAMPOLINE pTrampoline = NULL;
    //
    // Insure that there is a default region.
    //
    if (pCtx->s_pRegion == NULL && pCtx->s_pRegions != NULL)
    {
        pCtx->s_pRegion = pCtx->s_pRegions;
    }
    //
    // First check the default region for an valid free block.
    //
    if (pCtx->s_pRegion != NULL && pCtx->s_pRegion->pFree != NULL &&
        pCtx->s_pRegion->pFree >= pLo && pCtx->s_pRegion->pFree <= pHi)
    {
found_region:
        pTrampoline = pCtx->s_pRegion->pFree;
        //
        // do a last sanity check on region.
        //
        if (pTrampoline < pLo || pTrampoline > pHi)
        {
            return NULL;
        }
        pCtx->s_pRegion->pFree = pTrampoline->pbRemain;
        memset(pTrampoline->rbCode,0xCC,HOOK_MAX_JUMP_CODE_SIZE); // int3
        pTrampoline->pbRemain = DETOUR_TRAMPOLINE_USED;
        return pTrampoline;
    }
    //
    // Then check the existing regions for a valid free block.
    //
    for (pCtx->s_pRegion = pCtx->s_pRegions; pCtx->s_pRegion != NULL; pCtx->s_pRegion = pCtx->s_pRegion->pNext)
    {
        if (pCtx->s_pRegion != NULL && pCtx->s_pRegion->pFree != NULL &&
            pCtx->s_pRegion->pFree >= pLo && pCtx->s_pRegion->pFree <= pHi)
        {
            goto found_region;
        }
    }
    //
    // We need to allocate a new region.
    //
    // Round pbTarget down to 64KB block.
    pbTarget = pbTarget - (PtrToUlong(pbTarget) & 0xffff);
    PVOID pbTry = NULL;
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
    // Try anything below.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }
    if (pbTry != NULL)
    {
        pCtx->s_pRegion = (DETOUR_REGION*)pbTry;
        pCtx->s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
        pCtx->s_pRegion->pFree = NULL;
        pCtx->s_pRegion->pNext = pCtx->s_pRegions;
        pCtx->s_pRegions = pCtx->s_pRegion;
        //
        // Put everything on the free list.
        //
        PDETOUR_TRAMPOLINE pFree = NULL;
        pTrampoline = (PDETOUR_TRAMPOLINE)(pCtx->s_pRegion + 1);
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i >= 0; --i)
        {
            pTrampoline[i].pbRemain = pFree;
            pFree = &pTrampoline[i];
        }
        pCtx->s_pRegion->pFree = pFree;
        goto found_region;
    }
    return NULL;
}

static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline)
{
    PDETOUR_REGION pRegion = (PDETOUR_REGION)((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);
    if (DETOUR_REGION_SIGNATURE != pRegion->dwSignature)
    {
        return;
    }
    if (DETOUR_TRAMPOLINE_USED != pTrampoline->pbRemain)
    {
        return;
    }
    memset(pTrampoline,0,sizeof(*pTrampoline));
    pTrampoline->pbRemain = pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

static BOOL detour_is_region_empty(PDETOUR_REGION pRegion)
{
    // Stop if the region isn't a region (this would be bad).
    if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE)
    {
        return FALSE;
    }
    // Stop if any of the trampolines aren't free.
    PDETOUR_TRAMPOLINE pTrampoline = (PDETOUR_TRAMPOLINE)(pRegion + 1);
    for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; ++i)
    {
        if (DETOUR_TRAMPOLINE_USED == pTrampoline[i].pbRemain)
        {
            return FALSE;
        }
    }
    // OK, the region is empty.
    return TRUE;
}

static void detour_free_unused_trampoline_regions(PHOOK_CONTEXT pCtx)
{
    PDETOUR_REGION *ppRegionBase = &pCtx->s_pRegions;
    PDETOUR_REGION pRegion = pCtx->s_pRegions;
    while (pRegion != NULL)
    {
        if (detour_is_region_empty(pRegion))
        {
            *ppRegionBase = pRegion->pNext;
            VirtualFree(pRegion,0,MEM_RELEASE);
            pCtx->s_pRegion = NULL;
        }
        else
        {
            ppRegionBase = &pRegion->pNext;
        }
        pRegion = *ppRegionBase;
    }
}

/************************************************************************/
/* Memory operator By zzy                                               */
/************************************************************************/

static PT_void my_alloc(PHOOK_CONTEXT pCtx,size_t size)
{
    return pCtx->mem_mgr.alloc(pCtx->mem_mgr.userdata,size);
}

static T_void my_free(PHOOK_CONTEXT pCtx,PT_void ptr)
{
    pCtx->mem_mgr.free(pCtx->mem_mgr.userdata,ptr);
}

#define ALLOC(_s) my_alloc(pCtx,(_s))
#define FREE(_p) my_free(pCtx,(_p))

/************************************************************************/
/* Thread operator                                                      */
/************************************************************************/

T_bool HOOK_AddThread(PHOOK_CONTEXT pCtx,T_Dword TID)
{
    PHOOK_THREAD_INFO pThread,pCheckThread;
    if (NULL == pCtx)
    {
        return FALSE;
    }
    pThread = (PHOOK_THREAD_INFO)ALLOC(sizeof(HOOK_THREAD_INFO));
    if (NULL == pThread)
    {
        return FALSE;
    }
    pThread->TID = TID;
    pThread->Suspended = FALSE;
    pThread->hThread = OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,TID);
    if (NULL == pThread->hThread)
    {
        FREE(pThread);
        return FALSE;
    }
    pCheckThread = pCtx->ThreadList;
    while (pCheckThread)
    {
        if (TID == pCheckThread->TID)
        {
            break;
        }
        pCheckThread = pCheckThread->pNext;
    }
    if (pCheckThread)
    {
        // Exist.
        CloseHandle(pThread->hThread);
        FREE(pThread);
    }
    else
    {
        pThread->pNext = pCtx->ThreadList;
        pCtx->ThreadList = pThread;
    }
    return TRUE;
}

T_bool HOOK_RemoveThread(PHOOK_CONTEXT pCtx,T_Dword TID)
{
    PHOOK_THREAD_INFO pThread,pPrevThread;
    if (NULL == pCtx)
    {
        return FALSE;
    }
    pThread = pCtx->ThreadList;
    pPrevThread = NULL;
    while (pThread)
    {
        if (TID == pThread->TID)
        {
            break;
        }
        pPrevThread = pThread;
        pThread = pThread->pNext;
    }
    if (pThread)
    {
        if (pPrevThread)
        {
            pPrevThread->pNext = pThread->pNext;
        }
        else
        {
            pCtx->ThreadList = pThread->pNext;
        }
        CloseHandle(pThread->hThread);
        FREE(pThread);
    }
    return TRUE;
}

T_bool HOOK_SetAllThreadAlive(PHOOK_CONTEXT pCtx)
{
    PHOOK_THREAD_INFO pThread;
    T_bool bRet = TRUE;
    if (NULL == pCtx)
    {
        return FALSE;
    }
    pThread = pCtx->ThreadList;
    while (pThread)
    {
        if (pThread->Suspended)
        {
            if ((DWORD)-1 != ResumeThread(pThread->hThread))
            {
                pThread->Suspended = FALSE;
            }
            else
            {
                bRet = FALSE;
            }
        }
        pThread = pThread->pNext;
    }
    return bRet;
}

#if defined(_M_IX86)
    #define DETOURS_EIP         Eip
    #define DETOURS_EIP_TYPE    T_Dword
#elif defined(_M_X64)
    #define DETOURS_EIP         Rip
    #define DETOURS_EIP_TYPE    T_Qword
#else
    #error "not support."
#endif

static T_void AdjustThread(PHOOK_CONTEXT pCtx,PHOOK_DETOUR pDetour,HOOK_TODO HookTodo)
{
    PHOOK_THREAD_INFO pThread;
    CONTEXT cxt;
    pThread = pCtx->ThreadList;
    while (pThread)
    {
        cxt.ContextFlags = CONTEXT_CONTROL;
        if (pThread->Suspended && GetThreadContext(pThread->hThread,&cxt))
        {
            switch (HookTodo)
            {
            case TO_UNHOOK:
                if (pDetour->HookFunction)
                {
                    if (cxt.DETOURS_EIP == (DETOURS_EIP_TYPE)pDetour->ShellCode) // Only one instruct in shellcode.
                    {
                        cxt.DETOURS_EIP = (DETOURS_EIP_TYPE)pDetour->Target;
                        SetThreadContext(pThread->hThread,&cxt);
                    }
                }
                else
                {
                    if (cxt.DETOURS_EIP >= (DETOURS_EIP_TYPE)pDetour->ShellCode &&
                        cxt.DETOURS_EIP <= (DETOURS_EIP_TYPE)pDetour->ShellCode + pDetour->FixLength) // Include the final jump.
                    {
                        cxt.DETOURS_EIP += ((DETOURS_EIP_TYPE)pDetour->Target - (DETOURS_EIP_TYPE)pDetour->ShellCode);
                        SetThreadContext(pThread->hThread,&cxt);
                    }
                }
                if (cxt.DETOURS_EIP == (DETOURS_EIP_TYPE)pDetour->pTrampoline->rbCode)
                {
                    cxt.DETOURS_EIP = (DETOURS_EIP_TYPE)pDetour->Target;
                    SetThreadContext(pThread->hThread,&cxt);
                }
                break;
            case TO_HOOK:
                if ((!pDetour->HookFunction) &&
                    (cxt.DETOURS_EIP >= (DETOURS_EIP_TYPE)pDetour->Target) &&
                    (cxt.DETOURS_EIP < (DETOURS_EIP_TYPE)pDetour->Target + pDetour->FixLength))
                {
                    cxt.DETOURS_EIP += ((DETOURS_EIP_TYPE)pDetour->ShellCode - (DETOURS_EIP_TYPE)pDetour->Target);
                    SetThreadContext(pThread->hThread,&cxt);
                }
                break;
            case TO_FIX:
                if ((cxt.DETOURS_EIP >= (DETOURS_EIP_TYPE)pDetour->Target) &&
                    (cxt.DETOURS_EIP < (DETOURS_EIP_TYPE)pDetour->Target + pDetour->FixLength))
                {
                    cxt.DETOURS_EIP += ((DETOURS_EIP_TYPE)pDetour->ShellCode - (DETOURS_EIP_TYPE)pDetour->Target);
                    SetThreadContext(pThread->hThread,&cxt);
                }
                break;
            default:
                break;
            }
        }
        pThread = pThread->pNext;
    }
}

#undef DETOURS_EIP
#undef DETOURS_EIP_TYPE

static T_void SuspendAllThread(PHOOK_CONTEXT pCtx)
{
    PHOOK_THREAD_INFO pThread;
    T_Dword CurId = GetCurrentThreadId();
    pThread = pCtx->ThreadList;
    while (pThread)
    {
        if ((pThread->TID != CurId) && (!pThread->Suspended))
        {
            if ((DWORD)-1 != SuspendThread(pThread->hThread))
            {
                pThread->Suspended = TRUE;
            }
        }
        pThread = pThread->pNext;
    }
}

static T_void ResumeAllThread(PHOOK_CONTEXT pCtx)
{
    PHOOK_THREAD_INFO pThread;
    pThread = pCtx->ThreadList;
    while (pThread)
    {
        if (pThread->Suspended)
        {
            if ((DWORD)-1 != ResumeThread(pThread->hThread))
            {
                pThread->Suspended = FALSE;
            }
        }
        pThread = pThread->pNext;
    }
}

static T_void FreeThreadList(PHOOK_CONTEXT pCtx)
{
    PHOOK_THREAD_INFO pThread,pNext;
    pThread = pCtx->ThreadList;
    while (pThread)
    {
        pNext = pThread->pNext;
        // Freeing.
        if (pThread->Suspended)
        {
            ResumeThread(pThread->hThread);
        }
        CloseHandle(pThread->hThread);
        FREE(pThread);
        // Now next.
        pThread = pNext;
    }
    pCtx->ThreadList = NULL;
}

/************************************************************************/
/* Hook new and delete By zzy                                           */
/************************************************************************/

PHOOK_CONTEXT Hook_New(PMEM_MANAGER mem_mgr)
{
    if (NULL == mem_mgr)
    {
        return NULL;
    }
    PHOOK_CONTEXT pCtx;
    pCtx = (PHOOK_CONTEXT)mem_mgr->alloc(mem_mgr->userdata,sizeof(HOOK_CONTEXT));
    if (NULL == pCtx)
    {
        return NULL;
    }
    ZeroMemory(pCtx,sizeof(HOOK_CONTEXT));
    pCtx->mem_mgr = *mem_mgr;
    return pCtx;
}

T_bool Hook_Delete(PHOOK_CONTEXT pCtx)
{
    if (NULL==pCtx || pCtx->HookList!=NULL)
    {
        return FALSE;
    }
    detour_free_unused_trampoline_regions(pCtx);
    FreeThreadList(pCtx);
    PT_void userdata;
    typedef void (* pfnfree)(void * const userdata, void *p);
    pfnfree tmpfree;
    userdata = pCtx->mem_mgr.userdata;
    tmpfree = pCtx->mem_mgr.free;
    tmpfree(userdata,pCtx);
    return TRUE;
}

T_void Hook_FlushMemory(PHOOK_CONTEXT pCtx)
{
    if (NULL == pCtx)
    {
        return;
    }
    detour_free_unused_trampoline_regions(pCtx);
}

/************************************************************************/
/* Code maker By zzy                                                    */
/************************************************************************/

#if defined(_M_IX86)

#define HOOK_CLEAN_EAX_CODE_SIZE (2)
#define HOOK_SET_EAX_CODE_SIZE (5)
#define HOOK_PUSH_EAX_CODE_SIZE (1)

static inline T_void MakeJmp(T_byte code[HOOK_MAX_JUMP_CODE_SIZE],PT_void jmp_to)
{
    code[0] = 0xFF;
    code[1] = 0x25;
    *((PT_Bit32u)(&code[2])) = (T_Bit32u)(&code[8]);
    code[6] = 0;
    code[7] = 0;
    *((PT_Bit32u)(&code[8])) = (T_Bit32u)jmp_to;
}

static inline T_void ChangeJmpAddress(T_byte code[HOOK_MAX_JUMP_CODE_SIZE],PT_void jmp_to)
{
    InterlockedExchangePointer((PT_void *)(&code[8]),jmp_to);
}

static inline PT_void GetJmpAddr(T_byte code[HOOK_MAX_JUMP_CODE_SIZE])
{
    return (PT_void)(*((PT_Bit32u)(&code[8])));
}

static inline int CleanEAX(T_byte code[HOOK_CLEAN_EAX_CODE_SIZE])
{
    code[0] = 0x31;
    code[1] = 0xC0;
    return HOOK_CLEAN_EAX_CODE_SIZE;
}

static inline int SetEAX(T_byte code[HOOK_SET_EAX_CODE_SIZE],T_Bit32u value)
{
    code[0] = 0xB8;
    *((PT_Bit32u)(&code[1])) = value;
    return HOOK_SET_EAX_CODE_SIZE;
}

static inline int PushEAX(T_byte code[HOOK_PUSH_EAX_CODE_SIZE])
{
    code[0] = 0x50;
    return HOOK_PUSH_EAX_CODE_SIZE;
}

#elif defined(_M_X64)

#define HOOK_CLEAN_RAX_CODE_SIZE (3)
#define HOOK_SET_RAX_CODE_SIZE (10)
#define HOOK_PUSH_RAX_CODE_SIZE (1)

static inline T_void MakeJmp(T_byte code[HOOK_MAX_JUMP_CODE_SIZE],PT_void jmp_to)
{
    code[0] = 0xFF;
    code[1] = 0x25;
    *((PT_Bit32u)(&code[2])) = 2;
    code[6] = 0;
    code[7] = 0;
    *((PT_Bit64u)(&code[8])) = (T_Bit64u)jmp_to;
}

static inline T_void ChangeJmpAddress(T_byte code[HOOK_MAX_JUMP_CODE_SIZE],PT_void jmp_to)
{
    InterlockedExchangePointer((PT_void *)(&code[8]),jmp_to);
}

static inline PT_void GetJmpAddr(T_byte code[HOOK_MAX_JUMP_CODE_SIZE])
{
    return (PT_void)(*((PT_Bit64u)(&code[8])));
}

static inline int CleanRAX(T_byte code[HOOK_CLEAN_RAX_CODE_SIZE])
{
    code[0] = 0x48;
    code[1] = 0x31;
    code[2] = 0xC0;
    return HOOK_CLEAN_RAX_CODE_SIZE;
}

static inline int SetRAX(T_byte code[HOOK_SET_RAX_CODE_SIZE],T_Bit64u value)
{
    code[0] = 0x48;
    code[1] = 0xB8;
    *((PT_Bit64u)(&code[2])) = value;
    return HOOK_SET_RAX_CODE_SIZE;
}

static inline int PushRAX(T_byte code[HOOK_PUSH_RAX_CODE_SIZE])
{
    code[0] = 0x50;
    return HOOK_PUSH_RAX_CODE_SIZE;
}

#else
    #error "not support."
#endif

#if (defined(_M_IX86) || defined(_M_X64))

#define HOOK_NEAR_JUMP_CODE_SIZE (5)

static inline T_void MakeNearJmp(T_byte code[HOOK_NEAR_JUMP_CODE_SIZE],PT_void jmp_to)
{
    code[0] = 0xE9;
    *((PT_Bit32u)(&code[1])) = (T_Bit32u)(((T_address)jmp_to) - ((T_address)(&code[5])));
}

static inline T_void ChangeNearJmpAddress(T_byte code[HOOK_NEAR_JUMP_CODE_SIZE],PT_void jmp_to)
{
    *((PT_Bit32u)(&code[1])) = (T_Bit32u)(((T_address)jmp_to) - ((T_address)(&code[5])));
}

static inline PT_void GetNearJmpAddr(T_byte code[HOOK_NEAR_JUMP_CODE_SIZE])
{
    return (PT_void)(((T_address)(&code[5])) + (*((PT_Bit32s)(&code[1]))));
}

static inline T_void MakeInt3(PT_void Addr,T_Dword Length)
{
    memset(Addr,0xCC,Length);
}

static inline T_void MakeNop(PT_void Addr,T_Dword Length)
{
    memset(Addr,0x90,Length);
}

static T_bool IsPositionRelated(PDisEng_DECOMPOSED pDecomposed)
{
    T_Dword item;
    for (item=0;item<pDecomposed->OperandUsed;++item)
    {
        if (FlagOn(pDecomposed->Operand[item].RegType,DisEng_USE_BASE_GENERAL_REG))
        {
            if (R_RIP == pDecomposed->Operand[item].BaseGeneralReg)
            {
                //
                // Use eip,rip;
                //
                return TRUE;
            }
        }
        if (pDecomposed->Operand[item].UseJump)
        {
            //
            // Use jump/call etc.
            //
            return TRUE;
        }
    }
    return FALSE;
}

#define HOOK_END_STATUS_PREV_NOP 0x1
#define HOOK_END_STATUS_PREV_INT3 0x2
#define HOOK_END_STATUS_PREV_END 0x4

static T_bool CanCodeDetour(PDisEng_DECOMPOSED pDecomposed,PT_Dword pEndStatus)
{
    if (IsPositionRelated(pDecomposed))
    {
        return FALSE;
    }
    //
    // Check function end.
    //
    if ((I_JMP == pDecomposed->Opcode) ||
        (I_JMPF == pDecomposed->Opcode) ||
        (I_RET == pDecomposed->Opcode) ||
        (I_RETF == pDecomposed->Opcode))
    {
        if (FlagOn(*pEndStatus,HOOK_END_STATUS_PREV_END))
        {
            return FALSE;
        }
        SetFlag(*pEndStatus,HOOK_END_STATUS_PREV_END);
    }
    else if (I_INT3 == pDecomposed->Opcode)
    {
        SetFlag(*pEndStatus,HOOK_END_STATUS_PREV_END|HOOK_END_STATUS_PREV_INT3);
    }
    else if ((I_FNOP == pDecomposed->Opcode) ||
        (I_MULTIBYTE_NOP == pDecomposed->Opcode) ||
        (I_NOP == pDecomposed->Opcode))
    {
        if (FlagOn(*pEndStatus,HOOK_END_STATUS_PREV_END))
        {
            return FALSE;
        }
        SetFlag(*pEndStatus,HOOK_END_STATUS_PREV_NOP);
    }
    else
    {
        if (FlagOn(*pEndStatus,HOOK_END_STATUS_PREV_END))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static T_bool GetJumpTarget(PDisEng_DECOMPOSED pDecomposed,PT_byte pCode,PT_void *jmp_target)
{
    PT_void tmpData = NULL;
    if (1 == pDecomposed->OperandUsed)
    {
        if (pDecomposed->Operand[0].UseJump)
        {
            *jmp_target = (PT_void)pDecomposed->Operand[0].JumpRealAddr;
            return TRUE;
        }
        else
        {
            if (pDecomposed->Operand[0].UseSelector)
            {
                //
                // cs_selector:addr.
                //
                return FALSE;
            }
            if (pDecomposed->Operand[0].ImmSize)
            {
                //
                // Error.
                //
                return FALSE;
            }
            if (FlagOn(pDecomposed->Operand[0].RegType,~(DisEng_USE_BASE_GENERAL_REG|DisEng_USE_SEGMENT_REG)))
            {
                //
                // We can't deal with it.
                //
                return FALSE;
            }
            if (FlagOn(pDecomposed->Operand[0].RegType,DisEng_USE_BASE_GENERAL_REG))
            {
                if (R_RIP == pDecomposed->Operand[0].BaseGeneralReg)
                {
                    tmpData = pCode + pDecomposed->InstructLength;
                }
                else
                {
                    return FALSE;
                }
            }
            if (pDecomposed->Operand[0].dispSize)
            {
                tmpData = (PT_void)((PT_byte)tmpData
                    + ((DisEng_IS_NUMBER_SIGNED(pDecomposed->Operand[0].dispSize))?
                    (pDecomposed->Operand[0].disp.disps):
                    (pDecomposed->Operand[0].disp.dispu)));
            }
            if (tmpData)
            {
                __try
                {
                    switch (pDecomposed->Operand[0].PtrSize)
                    {
                    case PS_None:
                        *jmp_target = tmpData;
                        break;
                    case PS_BytePtr:
                        *jmp_target = (PT_void)*((PT_Bit8u)tmpData);
                        break;
                    case PS_WordPtr:
                        *jmp_target = (PT_void)*((PT_Bit16u)tmpData);
                        break;
                    case PS_DwordPtr:
                        *jmp_target = (PT_void)*((PT_Bit32u)tmpData);
                        break;
                    case PS_QwordPtr:
                        *jmp_target = (PT_void)*((PT_Bit64u)tmpData);
                        break;
                    default:
                        return FALSE;
                    }
                    return TRUE;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return FALSE;
                }
            }
        }
    }
    return FALSE;
}

static T_bool CheckIfInlineHooked(PZZY_DIS_CONTEXT pDisContext,PDisEng_DECOMPOSED pDecomposed,PHOOK_DETOUR pDetour)
{
    PT_byte pCode;
    PT_void jmp_target;
    pCode = (PT_byte)pDetour->Target;
    while (TRUE)
    {
        DisEng_Disasm(pDisContext,0,(T_address)pCode,pCode,NULL,pDecomposed);
        if ((I_JMP == pDecomposed->Opcode) || (I_JMPF == pDecomposed->Opcode))
        {
            if (GetJumpTarget(pDecomposed,pCode,&jmp_target))
            {
                if (pDecomposed->InstructLength >= HOOK_NEAR_JUMP_CODE_SIZE)
                {
                    pDetour->HookFunction = jmp_target;
                    return TRUE;
                }
                else
                {
                    pCode = (PT_byte)jmp_target;
                    pDetour->Target = jmp_target;
                    continue;
                }
            }
        }
        return FALSE;
    }
}

static T_bool NewDisEng(PHOOK_CONTEXT pCtx,PZZY_DIS_CONTEXT *ppDisCtx,PDisEng_DECOMPOSED *ppDe)
{
    PZZY_DIS_CONTEXT pDisContext = NULL;
    PDisEng_DECOMPOSED pDecomposed = NULL;
    pDisContext = DisEng_AllocateContext();
    if (!pDisContext)
    {
        return FALSE;
    }
    pDecomposed = (PDisEng_DECOMPOSED)ALLOC(sizeof(DisEng_DECOMPOSED));
    if (!pDecomposed)
    {
        DisEng_FreeContext(pDisContext);
        return FALSE;
    }
#if defined(_M_IX86)
    DisEng_SetCpuType(pDisContext,32);
#elif defined(_M_X64)
    DisEng_SetCpuType(pDisContext,64);
#else
    #error "not support."
#endif
    *ppDisCtx = pDisContext;
    *ppDe = pDecomposed;
    return TRUE;
}

static T_void DeleteDisEng(PHOOK_CONTEXT pCtx,PZZY_DIS_CONTEXT pDisCtx,PDisEng_DECOMPOSED pDe)
{
    FREE(pDe);
    DisEng_FreeContext(pDisCtx);
}

static T_bool MakeShellCode(PHOOK_CONTEXT pCtx,PHOOK_DETOUR pDetour)
{
    PZZY_DIS_CONTEXT pDisContext = NULL;
    PDisEng_DECOMPOSED pDecomposed = NULL;
    PT_byte pCode;
    T_Dword CurrentLength,FixLength;
    T_Dword EndStatus;
    if (!NewDisEng(pCtx,&pDisContext,&pDecomposed))
    {
        return FALSE;
    }
    if (CheckIfInlineHooked(pDisContext,pDecomposed,pDetour))
    {
        //
        // Deal with inline hooked function.
        //
        pDetour->FixLength = HOOK_NEAR_JUMP_CODE_SIZE;
        MakeInt3(pDetour->ShellCode,HOOK_MAX_SHELL_CODE_SIZE);
        MakeJmp(pDetour->ShellCode,pDetour->HookFunction);
        DeleteDisEng(pCtx,pDisContext,pDecomposed);
        return TRUE;
    }
    pCode = (PT_byte)pDetour->Target;
#if (defined(_M_IX86) || defined(_M_X64))
    //
    // We also need to deal with a kind special inline hook: call XXXX.(Caution this will cause error sometime,ignore.)
    //
    DisEng_Disasm(pDisContext,0,(T_address)pCode,pCode,NULL,pDecomposed);
    if ((I_CALL == pDecomposed->Opcode) || (I_CALLF == pDecomposed->Opcode))
    {
        PT_void CallTarget;
        if ((pDecomposed->InstructLength >= HOOK_NEAR_JUMP_CODE_SIZE) && GetJumpTarget(pDecomposed,pCode,&CallTarget))
        {
            PT_byte op_ptr;
            pDetour->FixLength = HOOK_NEAR_JUMP_CODE_SIZE;
            MakeInt3(pDetour->ShellCode,HOOK_MAX_SHELL_CODE_SIZE);
            op_ptr = pDetour->ShellCode;
#if defined(_M_IX86)
            //
            // mov eax,next_instr; push eax; xor eax,eax; jmp CallTarget;
            //
            op_ptr += SetEAX(op_ptr,(T_Bit32u)(pCode + pDecomposed->InstructLength));
            op_ptr += PushEAX(op_ptr);
            op_ptr += CleanEAX(op_ptr);
#else // defined(_M_X64)
            //
            // mov rax,next_instr; push rax; xor rax,rax; jmp CallTarget;
            //
            op_ptr += SetRAX(op_ptr,(T_Bit64u)(pCode + pDecomposed->InstructLength));
            op_ptr += PushRAX(op_ptr);
            op_ptr += CleanRAX(op_ptr);
#endif
            MakeJmp(op_ptr,CallTarget);
            DeleteDisEng(pCtx,pDisContext,pDecomposed);
            return TRUE;
        }
    }
#else
    #error "not support."
#endif
    FixLength = 0;
    EndStatus = 0;
    while (FixLength < HOOK_NEAR_JUMP_CODE_SIZE)
    {
        CurrentLength = DisEng_Disasm(pDisContext,0,(T_address)pCode,pCode,NULL,pDecomposed);
        //
        // Some time the function is not long enough.
        //
        if ((0 == CurrentLength) || (!CanCodeDetour(pDecomposed,&EndStatus)))
        {
            DeleteDisEng(pCtx,pDisContext,pDecomposed);
            return FALSE;
        }
        FixLength += CurrentLength;
        pCode += CurrentLength;
    }
    pDetour->FixLength = FixLength;
    MakeInt3(pDetour->ShellCode,HOOK_MAX_SHELL_CODE_SIZE);
    memcpy(pDetour->ShellCode,pDetour->Target,FixLength);
    MakeJmp(&pDetour->ShellCode[FixLength],(PT_void)((PT_byte)pDetour->Target + FixLength));
    DeleteDisEng(pCtx,pDisContext,pDecomposed);
    return TRUE;
}

static PT_void IsJump(PHOOK_CONTEXT pCtx,PT_void Target)
{
    PZZY_DIS_CONTEXT pDisContext = NULL;
    PDisEng_DECOMPOSED pDecomposed = NULL;
    PT_void RetPtr = NULL;
    PT_byte pCode = (PT_byte)Target;
    if (!NewDisEng(pCtx,&pDisContext,&pDecomposed))
    {
        return NULL;
    }
    if (DisEng_Disasm(pDisContext,0,(T_address)pCode,pCode,NULL,pDecomposed))
    {
        if ((I_JMP == pDecomposed->Opcode) ||
            (I_JMPF == pDecomposed->Opcode) ||
            (I_CALL == pDecomposed->Opcode) ||
            (I_CALLF == pDecomposed->Opcode))
        {
            GetJumpTarget(pDecomposed,pCode,&RetPtr);
        }
    }
    DeleteDisEng(pCtx,pDisContext,pDecomposed);
    return RetPtr;
}

#else
    #error "not support."
#endif

static HOOK_STATUS DetourWithShellCode(PHOOK_CONTEXT pCtx,PHOOK_DETOUR pDetour,HOOK_TODO HookTodo)
{
    __try
    {
        DWORD old1,old2;
        switch (HookTodo)
        {
        case TO_UNHOOK:
            {
                if (pDetour->HookFunction)
                {
                    // Caution.
                    if (0 != memcmp(pDetour->Target,pDetour->FixCode,pDetour->FixLength))
                    {
                        // Maybe the former hook has been freed or new one establish.
                        // Don't touch any thing.
                        if (IsJump(pCtx,pDetour->Target))
                        {
                            // Ok,new one,so we can't free.
                            return HOOK_STATUS_FAILED;
                        }
                        // If old one free,just free myself.
                        break;
                    }
                    // Ok,safe.
                }
                VirtualProtect(pDetour->Target,pDetour->FixLength,PAGE_EXECUTE_READWRITE,&old1);
                memcpy(pDetour->Target,pDetour->OriginalCode,pDetour->FixLength);
                VirtualProtect(pDetour->Target,pDetour->FixLength,old1,&old2);
                FlushInstructionCache(GetCurrentProcess(),pDetour->Target,pDetour->FixLength);
            }
            break;
        case TO_HOOK:
            {
                if (!MakeShellCode(pCtx,pDetour))
                {
                    return HOOK_STATUS_FAILED;
                }
                // Now Detour's target is changed check rehook.
                PHOOK_DETOUR pTest;
                pTest = pCtx->HookList;
                while (pTest)
                {
                    if (pTest->Target == pDetour->Target)
                    {
                        return HOOK_STATUS_ALREADY_HOOKED;
                    }
                    pTest = pTest->pNext;
                }
                // Ok, hook.
                MakeJmp(pDetour->pTrampoline->rbCode,pDetour->ShellCode);
                memcpy(pDetour->OriginalCode,pDetour->Target,pDetour->FixLength);
                VirtualProtect(pDetour->Target,pDetour->FixLength,PAGE_EXECUTE_READWRITE,&old1);
                MakeNearJmp((PT_byte)pDetour->Target,pDetour->pTrampoline->rbCode);
                MakeInt3((PT_byte)pDetour->Target + HOOK_NEAR_JUMP_CODE_SIZE,pDetour->FixLength - HOOK_NEAR_JUMP_CODE_SIZE);
                VirtualProtect(pDetour->Target,pDetour->FixLength,old1,&old2);
                FlushInstructionCache(GetCurrentProcess(),pDetour->Target,pDetour->FixLength);
                memcpy(pDetour->FixCode,pDetour->Target,pDetour->FixLength);
            }
            break;
        case TO_FIX:
            {
                if (pDetour->HookFunction)
                {
                    // Caution.
                    if (0 != memcmp(pDetour->Target,pDetour->OriginalCode,pDetour->FixLength))
                    {
                        // Maybe former one has been freed or new hook is established.
                        if (IsJump(pCtx,pDetour->Target))
                        {
                            // Oh,new one.
                            // Don't do any thing.
                            return HOOK_STATUS_FAILED;
                        }
                        // Old one restore code to it's real format.
                        // Analysis and rehook.
                        if (!VirtualProtect(pDetour->Target,pDetour->FixLength,PAGE_EXECUTE_READWRITE,&old1))
                        {
                            // This time must success.
                            return HOOK_STATUS_FAILED;
                        }
                        // First code is not jump so target will not change.
                        if (!MakeShellCode(pCtx,pDetour))
                        {
                            return HOOK_STATUS_FAILED;
                        }
                        // Trampoline is already ok.
                        memcpy(pDetour->OriginalCode,pDetour->Target,pDetour->FixLength);
                        // Set again for safety.
                        VirtualProtect(pDetour->Target,pDetour->FixLength,PAGE_EXECUTE_READWRITE,&old2);
                        MakeNearJmp((PT_byte)pDetour->Target,pDetour->pTrampoline->rbCode);
                        MakeInt3((PT_byte)pDetour->Target + HOOK_NEAR_JUMP_CODE_SIZE,pDetour->FixLength - HOOK_NEAR_JUMP_CODE_SIZE);
                        VirtualProtect(pDetour->Target,pDetour->FixLength,old1,&old2);
                        FlushInstructionCache(GetCurrentProcess(),pDetour->Target,pDetour->FixLength);
                        memcpy(pDetour->FixCode,pDetour->Target,pDetour->FixLength);
                        break;
                    }
                    // Safe to rehook it.
                }
                VirtualProtect(pDetour->Target,pDetour->FixLength,PAGE_EXECUTE_READWRITE,&old1);
                memcpy(pDetour->Target,pDetour->FixCode,pDetour->FixLength);
                VirtualProtect(pDetour->Target,pDetour->FixLength,old1,&old2);
                FlushInstructionCache(GetCurrentProcess(),pDetour->Target,pDetour->FixLength);
                break;
            }
        default:
            return HOOK_STATUS_FAILED;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return HOOK_STATUS_MEMORY_DENIED;
    }
    return HOOK_STATUS_SUCCESS;
}

HOOK_STATUS Hook_DetourAttach(PHOOK_CONTEXT pCtx,PT_void Target,PT_void To,PT_void *pCookie,PT_void *pJumpBack)
{
    PHOOK_DETOUR pDetour;
    HOOK_STATUS Status;
    if (NULL==pCtx || NULL==Target || NULL==To)
    {
        return HOOK_STATUS_FAILED;
    }
    pDetour = pCtx->HookList;
    while (pDetour)
    {
        if (pDetour->OriginalTarget == Target)
        {
            return HOOK_STATUS_ALREADY_HOOKED;
        }
        pDetour = pDetour->pNext;
    }
    pDetour = (PHOOK_DETOUR)ALLOC(sizeof(HOOK_DETOUR));
    if (NULL == pDetour)
    {
        return HOOK_STATUS_INSUFFICIENT_MEMORY;
    }
    ZeroMemory(pDetour,sizeof(HOOK_DETOUR));
    pDetour->pSelf = pDetour;
    pDetour->To = To;
    pDetour->Target = Target;
    pDetour->OriginalTarget = Target;
    pDetour->pTrampoline = detour_alloc_trampoline(pCtx,(PT_byte)Target);
    if (NULL == pDetour->pTrampoline)
    {
        FREE(pDetour);
        return HOOK_STATUS_INSUFFICIENT_MEMORY;
    }
    SuspendAllThread(pCtx);
    Status = DetourWithShellCode(pCtx,pDetour,TO_HOOK);
    if (HOOK_STATUS_SUCCESS != Status)
    {
        ResumeAllThread(pCtx);
        detour_free_trampoline(pDetour->pTrampoline);
        FREE(pDetour);
        return Status;
    }
    // Adjust thread.
    AdjustThread(pCtx,pDetour,TO_HOOK);
    ResumeAllThread(pCtx);
    // Success,add in list.
    pDetour->pNext = pCtx->HookList;
    pCtx->HookList = pDetour;
    // Set cookie & jump back.
    if (pCookie)
    {
        *pCookie = pDetour;
    }
    if (pJumpBack)
    {
        *pJumpBack = pDetour->ShellCode;
    }
    return HOOK_STATUS_SUCCESS;
}

HOOK_STATUS Hook_DetourDetach(PHOOK_CONTEXT pCtx,PT_void Cookie)
{
    PHOOK_DETOUR pDetour,pPrev;
    HOOK_STATUS Status;
    if (NULL==pCtx || NULL==Cookie)
    {
        return HOOK_STATUS_FAILED;
    }
    // Check cookie.
    __try
    {
        pDetour = (PHOOK_DETOUR)Cookie;
        if (pDetour->pSelf != pDetour)
        {
            return HOOK_STATUS_FAILED;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return HOOK_STATUS_FAILED;
    }
    ChangeJmpAddress(pDetour->pTrampoline->rbCode,pDetour->ShellCode);
    pPrev = NULL;
    pDetour = pCtx->HookList;
    while (pDetour)
    {
        if (pDetour == (PHOOK_DETOUR)Cookie)
        {
            break;
        }
        pPrev = pDetour;
        pDetour = pDetour->pNext;
    }
    if (NULL == pDetour)
    {
        return HOOK_STATUS_FAILED;
    }
    SuspendAllThread(pCtx);
    Status = DetourWithShellCode(pCtx,pDetour,TO_UNHOOK);
    if (HOOK_STATUS_SUCCESS != Status)
    {
        ResumeAllThread(pCtx);
        return Status;
    }
    // Adjust thread.
    AdjustThread(pCtx,pDetour,TO_UNHOOK);
    ResumeAllThread(pCtx);
    // Remove from list.
    if (pPrev)
    {
        pPrev->pNext = pDetour->pNext;
    }
    else
    {
        pCtx->HookList = pDetour->pNext;
    }
    detour_free_trampoline(pDetour->pTrampoline);
    pDetour->pSelf = NULL; // Clean the flag.
    FREE(pDetour);
    return HOOK_STATUS_SUCCESS;
}

T_bool Hook_StartFilter(PHOOK_CONTEXT pCtx,PT_void Cookie)
{
    PHOOK_DETOUR pDetour;
    if (NULL==pCtx || NULL==Cookie)
    {
        return FALSE;
    }
    // Check cookie.
    __try
    {
        pDetour = (PHOOK_DETOUR)Cookie;
        if (pDetour->pSelf != pDetour)
        {
            return FALSE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    ChangeJmpAddress(pDetour->pTrampoline->rbCode,pDetour->To);
    return TRUE;
}

T_bool Hook_StopFilter(PHOOK_CONTEXT pCtx,PT_void Cookie)
{
    PHOOK_DETOUR pDetour;
    if (NULL==pCtx || NULL==Cookie)
    {
        return FALSE;
    }
    // Check cookie.
    __try
    {
        pDetour = (PHOOK_DETOUR)Cookie;
        if (pDetour->pSelf != pDetour)
        {
            return FALSE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    ChangeJmpAddress(pDetour->pTrampoline->rbCode,pDetour->ShellCode);
    return TRUE;
}

T_bool Hook_FixDetour(PHOOK_CONTEXT pCtx,PT_Dword pFixedCount)
{
    PZZY_DIS_CONTEXT pDisContext = NULL;
    PDisEng_DECOMPOSED pDecomposed = NULL;
    PHOOK_DETOUR pDetour;
    T_Dword FixCount = 0;
    if (NULL == pCtx)
    {
        return FALSE;
    }
    if (!NewDisEng(pCtx,&pDisContext,&pDecomposed))
    {
        return FALSE;
    }
    pDetour = pCtx->HookList;
    while (pDetour)
    {
        T_bool bNeedFix = TRUE;
        PT_byte pCode = (PT_byte)pDetour->Target;
        if (0 != DisEng_Disasm(pDisContext,0,(T_address)pCode,pCode,NULL,pDecomposed))
        {
            if (I_JMP == pDecomposed->Opcode ||
                I_JMPF == pDecomposed->Opcode ||
                I_CALL == pDecomposed->Opcode ||
                I_CALLF == pDecomposed->Opcode)
            {
                PT_void jmp_to;
                if (GetJumpTarget(pDecomposed,pCode,&jmp_to))
                {
                    if (jmp_to != pDetour->HookFunction)
                    {
                        bNeedFix = FALSE;
                    }
                }
            }
        }
        if (bNeedFix)
        {
            if (0 == FixCount)
            {
                SuspendAllThread(pCtx);
            }
            ++FixCount;
            if (HOOK_STATUS_SUCCESS == DetourWithShellCode(pCtx,pDetour,TO_FIX))
            {
                AdjustThread(pCtx,pDetour,TO_FIX);
            }
        }
        pDetour = pDetour->pNext;
    }
    if (FixCount)
    {
        ResumeAllThread(pCtx);
    }
    if (pFixedCount)
    {
        *pFixedCount = FixCount;
    }
    DeleteDisEng(pCtx,pDisContext,pDecomposed);
    return TRUE;
}

#define IsOverlapped(_p1,_s1,_p2,_s2) (!(((PT_byte)(_p1) >= (PT_byte)(_p2)+(_s2)) || ((PT_byte)(_p1)+(_s1) <= (PT_byte)(_p2))))

T_bool Hook_IsDetourContextMemory(PHOOK_CONTEXT pCtx,PT_void pStart,T_address Length)
{
    PHOOK_DETOUR pDetour;
    if (NULL==pCtx || 0==Length)
    {
        return FALSE;
    }
    pDetour = pCtx->HookList;
    while (pDetour)
    {
        if (IsOverlapped(pDetour->Target,pDetour->FixLength,pStart,Length))
        {
            return TRUE;
        }
        pDetour = pDetour->pNext;
    }
    return FALSE;
}

#undef IsOverlapped
