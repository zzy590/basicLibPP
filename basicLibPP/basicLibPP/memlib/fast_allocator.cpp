//////////////////////////////////////////////////////////////////////////
// For allocate fixed size memory

#include "../basic_fun.h"

typedef struct _BLPP_FAST_ALLOCATOR_CONTEXT
{
    BLPP_QUEUED_LOCK Lock;
    T_ListEntry MemListHead;
    T_Dword Size;
    T_Dword Depth;
    T_Dword NowDepth;
} BLPP_FAST_ALLOCATOR_CONTEXT, *PBLPP_FAST_ALLOCATOR_CONTEXT;

//
// Functions.
//

PBLPP_FAST_ALLOCATOR_CONTEXT blpp_mem_createFastAllocator(T_Dword Size,T_Dword Depth)
{
    PBLPP_FAST_ALLOCATOR_CONTEXT pCtx;
    pCtx = (PBLPP_FAST_ALLOCATOR_CONTEXT)blpp_mem_alloc(sizeof(BLPP_FAST_ALLOCATOR_CONTEXT));
    if (NULL == pCtx)
    {
        return NULL;
    }
    LOCK_InitializeQueuedLock(&pCtx->Lock);
    T_ListEntry_InitListHead(&pCtx->MemListHead);
    pCtx->Size = (Size>sizeof(T_ListEntry))?(Size):(sizeof(T_ListEntry));
    pCtx->Depth = Depth;
    pCtx->NowDepth = 0;
    return pCtx;
}

T_void blpp_mem_closeFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx)
{
    PT_void pTmp;
    // Flush lock;
    LOCK_AcquireReleaseQueuedLockExclusive(&pCtx->Lock);
    while (pTmp = (PT_void)T_ListEntry_RemoveHeadList(&pCtx->MemListHead))
    {
        blpp_mem_free(pTmp);
    }
    blpp_mem_free(pCtx);
}

PT_void blpp_mem_allocateFromFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx)
{
    PT_void pTmp;
    T_Dword nSize;
    LOCK_AcquireQueuedLockExclusive(&pCtx->Lock);
    pTmp = (PT_void)T_ListEntry_RemoveHeadList(&pCtx->MemListHead);
    if (pTmp)
    {
        --(pCtx->NowDepth);
    }
    nSize = pCtx->Size;
    LOCK_ReleaseQueuedLockExclusive(&pCtx->Lock);
    if (NULL == pTmp)
    {
        pTmp = blpp_mem_alloc(nSize);
    }
    else
    {
        memset(pTmp,0,nSize);
    }
    return pTmp;
}

T_void blpp_mem_freeToFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx,PT_void Ptr)
{
    LOCK_AcquireQueuedLockExclusive(&pCtx->Lock);
    if (pCtx->NowDepth < pCtx->Depth)
    {
        T_ListEntry_InsertTailList(&pCtx->MemListHead,(PT_ListEntry)Ptr);
        ++(pCtx->NowDepth);
        Ptr = NULL;
    }
    LOCK_ReleaseQueuedLockExclusive(&pCtx->Lock);
    if (Ptr)
    {
        blpp_mem_free(Ptr);
    }
}
