#pragma once

#include <Windows.h>
#include "../my_krnlDef/krnlDef.h"

#define LOCK_QUEUED_LOCK_OWNED ((ULONG_PTR)0x1)
#define LOCK_QUEUED_LOCK_OWNED_SHIFT 0
#define LOCK_QUEUED_LOCK_WAITERS ((ULONG_PTR)0x2)

// Valid only if Waiters = 0
#define LOCK_QUEUED_LOCK_SHARED_INC ((ULONG_PTR)0x4)
#define LOCK_QUEUED_LOCK_SHARED_SHIFT 2

// Valid only if Waiters = 1
#define LOCK_QUEUED_LOCK_TRAVERSING ((ULONG_PTR)0x4)
#define LOCK_QUEUED_LOCK_MULTIPLE_SHARED ((ULONG_PTR)0x8)

typedef struct DECLSPEC_ALIGN(8) _BLPP_QUEUED_LOCK
{
    ULONG_PTR Value;
} BLPP_QUEUED_LOCK, *PBLPP_QUEUED_LOCK;

#define BLPP_QUEUED_LOCK_INIT { 0 }

VOID LOCK_QueuedLockUninitialization();

BOOLEAN LOCK_QueuedLockInitialization();

FORCEINLINE VOID LOCK_InitializeQueuedLock
(
    __out PBLPP_QUEUED_LOCK QueuedLock
)
{
    QueuedLock->Value = 0;
}

VOID
__fastcall
LOCK_fAcquireQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
);

VOID
__fastcall
LOCK_fAcquireQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
);

VOID
__fastcall
LOCK_fReleaseQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
);

VOID
__fastcall
LOCK_fReleaseQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
);

VOID __fastcall LOCK_fWakeForReleaseQueuedLock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value
);

// Inline functions

FORCEINLINE VOID LOCK_AcquireQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    if (_InterlockedBitTestAndSetPointer((PLONG_PTR)&QueuedLock->Value, LOCK_QUEUED_LOCK_OWNED_SHIFT))
    {
        // Owned bit was already set. Slow path.
        LOCK_fAcquireQueuedLockExclusive(QueuedLock);
    }
}

FORCEINLINE VOID LOCK_AcquireQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    if ((ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)(LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_SHARED_INC),(PVOID)0) != 0)
    {
        LOCK_fAcquireQueuedLockShared(QueuedLock);
    }
}

FORCEINLINE BOOLEAN LOCK_TryAcquireQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    if (!_InterlockedBitTestAndSetPointer((PLONG_PTR)&QueuedLock->Value, LOCK_QUEUED_LOCK_OWNED_SHIFT))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

FORCEINLINE VOID LOCK_ReleaseQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    value = (ULONG_PTR)_InterlockedExchangeAddPointer((PLONG_PTR)&QueuedLock->Value, -(LONG_PTR)LOCK_QUEUED_LOCK_OWNED);
    if ((value & (LOCK_QUEUED_LOCK_WAITERS | LOCK_QUEUED_LOCK_TRAVERSING)) == LOCK_QUEUED_LOCK_WAITERS)
    {
        LOCK_fWakeForReleaseQueuedLock(QueuedLock, value - LOCK_QUEUED_LOCK_OWNED);
    }
}

FORCEINLINE VOID LOCK_ReleaseQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    value = LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_SHARED_INC;
    if ((ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)0,(PVOID)value) != value)
    {
        LOCK_fReleaseQueuedLockShared(QueuedLock);
    }
}

FORCEINLINE VOID LOCK_AcquireReleaseQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    BOOLEAN owned;
    MemoryBarrier();
    owned = !!(QueuedLock->Value & LOCK_QUEUED_LOCK_OWNED);
    MemoryBarrier();
    if (owned)
    {
        LOCK_AcquireQueuedLockExclusive(QueuedLock);
        LOCK_ReleaseQueuedLockExclusive(QueuedLock);
    }
}

FORCEINLINE BOOLEAN LOCK_TryAcquireReleaseQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    BOOLEAN owned;
    // Need two memory barriers because we don't want the
    // compiler re-ordering the following check in either
    // direction.
    MemoryBarrier();
    owned = !(QueuedLock->Value & LOCK_QUEUED_LOCK_OWNED);
    MemoryBarrier();
    return owned;
}
