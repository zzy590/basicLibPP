/**
 * Queued lock, a.k.a. push lock (kernel-mode) or slim reader-writer lock
 * (user-mode).
 *
 * The queued lock is:
 * * Around 10% faster than the fast lock.
 * * Only the size of a pointer.
 * * Low on resource usage (no additional kernel objects are
 *   created for blocking).
 *
 * The usual flags are used for contention-free
 * acquire/release. When there is contention, stack-based
 * wait blocks are chained. The first wait block contains
 * the shared owners count which is decremented by
 * shared releasers.
 *
 * Naturally these wait blocks would be chained
 * in FILO order, but list optimization is done for two purposes:
 * * Finding the last wait block (where the shared owners
 *   count is stored). This is implemented by the Last pointer.
 * * Unblocking the wait blocks in FIFO order. This is
 *   implemented by the Previous pointer.
 *
 * The optimization is incremental - each optimization run
 * will stop at the first optimized wait block. Any needed
 * optimization is completed just before waking waiters.
 *
 * The waiters list/chain has the following restrictions:
 * * At any time wait blocks may be pushed onto the list.
 * * While waking waiters, the list may not be traversed
 *   nor optimized.
 * * When there are multiple shared owners, shared releasers
 *   may traverse the list (to find the last wait block).
 *   This is not an issue because waiters wouldn't be woken
 *   until there are no more shared owners.
 * * List optimization may be done at any time except for
 *   when someone else is waking waiters. This is controlled
 *   by the traversing bit.
 *
 * The traversing bit has the following rules:
 * * The list may be optimized only after the traversing bit
 *   is set, checking that it wasn't set already.
 *   If it was set, it would indicate that someone else is
 *   optimizing the list or waking waiters.
 * * Before waking waiters the traversing bit must be set.
 *   If it was set already, just clear the owned bit.
 * * If during list optimization the owned bit is detected
 *   to be cleared, the function begins waking waiters. This
 *   is because the owned bit is cleared when a releaser
 *   fails to set the traversing bit.
 *
 * Blocking is implemented through a process-wide keyed event.
 * A spin count is also used before blocking on the keyed
 * event.
 *
 * Queued locks can act as condition variables, with
 * wait, pulse and pulse all support. Waiters are released
 * in FIFO order.
 *
 * Queued locks can act as wake events. These are designed
 * for tiny one-bit locks which share a single event to block
 * on. Spurious wake-ups are a part of normal operation.
 */

#include "QueuedLock.h"
#include <assert.h>

// Lock.

#define LOCK_QUEUED_LOCK_FLAGS ((ULONG_PTR)0xf)

#define LOCK_GetQueuedLockSharedOwners(Value) ((ULONG_PTR)(Value) >> LOCK_QUEUED_LOCK_SHARED_SHIFT)
#define LOCK_GetQueuedLockWaitBlock(Value) ((PLOCK_QUEUED_WAIT_BLOCK)((ULONG_PTR)(Value) & ~LOCK_QUEUED_LOCK_FLAGS))

#define LOCK_QUEUED_WAITER_EXCLUSIVE 0x1
#define LOCK_QUEUED_WAITER_SPINNING 0x2
#define LOCK_QUEUED_WAITER_SPINNING_SHIFT 1

typedef struct DECLSPEC_ALIGN(16) _LOCK_QUEUED_WAIT_BLOCK
{
    /** A pointer to the next wait block, i.e. the
     * wait block pushed onto the list before this
     * one.
     */
    struct _LOCK_QUEUED_WAIT_BLOCK *Next;
    /** A pointer to the previous wait block, i.e. the
     * wait block pushed onto the list after this
     * one.
     */
    struct _LOCK_QUEUED_WAIT_BLOCK *Previous;
    /** A pointer to the last wait block, i.e. the
     * first waiter pushed onto the list.
     */
    struct _LOCK_QUEUED_WAIT_BLOCK *Last;
    ULONG SharedOwners;
    ULONG Flags;
} LOCK_QUEUED_WAIT_BLOCK, *PLOCK_QUEUED_WAIT_BLOCK;

VOID __fastcall LOCK_pfWakeQueuedLock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value
);

static HANDLE LOCK_QueuedLockKeyedEventHandle = NULL;
static ULONG LOCK_QueuedLockSpinCount = 2000;

#define __mayRaise
#define LOCK_RaiseStatus(Status) {ExitProcess(~0u);}

VOID LOCK_QueuedLockUninitialization()
{
    if (LOCK_QueuedLockKeyedEventHandle)
    {
        NtClose(LOCK_QueuedLockKeyedEventHandle);
        LOCK_QueuedLockKeyedEventHandle = NULL;
    }
}

BOOLEAN LOCK_QueuedLockInitialization()
{
    SYSTEM_INFO SI;
    if (!NT_SUCCESS(NtCreateKeyedEvent(&LOCK_QueuedLockKeyedEventHandle,KEYEDEVENT_ALL_ACCESS,NULL,0)))
    {
        return FALSE;
    }
    GetSystemInfo(&SI);
    if ((ULONG)SI.dwNumberOfProcessors > 1)
    {
        LOCK_QueuedLockSpinCount = 4000;
    }
    else
    {
        LOCK_QueuedLockSpinCount = 0;
    }
    return TRUE;
}

/**
 * Pushes a wait block onto a queued lock's waiters list.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 * \param Exclusive Whether the wait block is in exclusive
 * mode.
 * \param WaitBlock A variable which receives the resulting
 * wait block structure.
 * \param Optimize A variable which receives a boolean
 * indicating whether to optimize the waiters list.
 * \param NewValue The old value of the queued lock. This
 * value is useful only if the function returns FALSE.
 * \param CurrentValue The new value of the queued lock. This
 * value is useful only if the function returns TRUE.
 *
 * \return TRUE if the wait block was pushed onto the waiters
 * list, otherwise FALSE.
 *
 * \remarks
 * \li The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_OWNED.
 * \li Do not move the wait block location after this
 * function is called.
 * \li The \a Optimize boolean is a hint to call
 * LOCK_pfOptimizeQueuedLockList() if the function succeeds. It is
 * recommended, but not essential that this occurs.
 * \li Call LOCK_pBlockOnQueuedWaitBlock() to wait for the wait
 * block to be unblocked.
 */
FORCEINLINE BOOLEAN LOCK_pPushQueuedWaitBlock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value,
    __in BOOLEAN Exclusive,
    __out PLOCK_QUEUED_WAIT_BLOCK WaitBlock,
    __out PBOOLEAN Optimize,
    __out PULONG_PTR NewValue,
    __out PULONG_PTR CurrentValue
)
{
    ULONG_PTR newValue;
    BOOLEAN optimize;
    WaitBlock->Previous = NULL; // set later by optimization
    optimize = FALSE;
    if (Exclusive)
    {
        WaitBlock->Flags = LOCK_QUEUED_WAITER_EXCLUSIVE | LOCK_QUEUED_WAITER_SPINNING;
    }
    else
    {
        WaitBlock->Flags = LOCK_QUEUED_WAITER_SPINNING;
    }
    if (Value & LOCK_QUEUED_LOCK_WAITERS)
    {
        // We're not the first waiter.
        WaitBlock->Last = NULL; // set later by optimization
        WaitBlock->Next = LOCK_GetQueuedLockWaitBlock(Value);
        WaitBlock->SharedOwners = 0;
        // Push our wait block onto the list.
        // Set the traversing bit because we'll be optimizing the list.
        newValue = ((ULONG_PTR)WaitBlock) | (Value & LOCK_QUEUED_LOCK_FLAGS) | LOCK_QUEUED_LOCK_TRAVERSING;
        if (!(Value & LOCK_QUEUED_LOCK_TRAVERSING))
        {
            optimize = TRUE;
        }
    }
    else
    {
        // We're the first waiter.
        WaitBlock->Last = WaitBlock; // indicate that this is the last wait block
        if (Exclusive)
        {
            // We're the first waiter. Save the shared owners count.
            WaitBlock->SharedOwners = (ULONG)LOCK_GetQueuedLockSharedOwners(Value);
            if (WaitBlock->SharedOwners > 1)
            {
                newValue = ((ULONG_PTR)WaitBlock) | LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_WAITERS | LOCK_QUEUED_LOCK_MULTIPLE_SHARED;
            }
            else
            {
                newValue = ((ULONG_PTR)WaitBlock) | LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_WAITERS;
            }
        }
        else
        {
            // We're waiting in shared mode, which means there can't
            // be any shared owners (otherwise we would've acquired
            // the lock already).
            WaitBlock->SharedOwners = 0;
            newValue = ((ULONG_PTR)WaitBlock) | LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_WAITERS;
        }
    }
    *Optimize = optimize;
    *CurrentValue = newValue;
    newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)Value);
    *NewValue = newValue;
    return newValue == Value;
}

/**
 * Finds the last wait block in the waiters list.
 *
 * \param Value The current value of the queued lock.
 *
 * \return A pointer to the last wait block.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS,
 * \ref LOCK_QUEUED_LOCK_MULTIPLE_SHARED or
 * \ref LOCK_QUEUED_LOCK_TRAVERSING.
 */
FORCEINLINE PLOCK_QUEUED_WAIT_BLOCK LOCK_pFindLastQueuedWaitBlock
(
    __in ULONG_PTR Value
)
{
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    PLOCK_QUEUED_WAIT_BLOCK lastWaitBlock;
    waitBlock = LOCK_GetQueuedLockWaitBlock(Value);
    // Traverse the list until we find the last wait block.
    // The Last pointer should be set by list optimization,
    // allowing us to skip all, if not most of the wait blocks.
    while (TRUE)
    {
        lastWaitBlock = waitBlock->Last;
        if (lastWaitBlock)
        {
            // Follow the Last pointer. This can mean two
            // things: the pointer was set by list optimization,
            // or this wait block is actually the last wait block
            // (set when it was pushed onto the list).
            waitBlock = lastWaitBlock;
            break;
        }
        waitBlock = waitBlock->Next;
    }
    return waitBlock;
}

/**
 * Waits for a wait block to be unblocked.
 *
 * \param WaitBlock A wait block.
 * \param Spin TRUE to spin, FALSE to block immediately.
 * \param Timeout A timeout value.
 */
__mayRaise FORCEINLINE NTSTATUS LOCK_pBlockOnQueuedWaitBlock
(
    __inout PLOCK_QUEUED_WAIT_BLOCK WaitBlock,
    __in BOOLEAN Spin,
    __in_opt PLARGE_INTEGER Timeout
)
{
    NTSTATUS status;
    ULONG i;
    if (Spin)
    {
        for (i = LOCK_QueuedLockSpinCount; i != 0; --i)
        {
            if (!(*(volatile ULONG *)&WaitBlock->Flags & LOCK_QUEUED_WAITER_SPINNING))
            {
                return STATUS_SUCCESS;
            }
            YieldProcessor();
        }
    }
    if (_interlockedbittestandreset((PLONG)&WaitBlock->Flags, LOCK_QUEUED_WAITER_SPINNING_SHIFT))
    {
        status = NtWaitForKeyedEvent(LOCK_QueuedLockKeyedEventHandle,WaitBlock,FALSE,Timeout);
        // If an error occurred (timeout is not an error), raise an exception
        // as it is nearly impossible to recover from this situation.
        if (!NT_SUCCESS(status))
        {
            //
            // Try again.
            //
            status = NtWaitForKeyedEvent(LOCK_QueuedLockKeyedEventHandle,WaitBlock,FALSE,Timeout);
            if (!NT_SUCCESS(status))
            {
                //
                // Oh, no.
                //
                LOCK_RaiseStatus(status);
            }
        }
    }
    else
    {
        status = STATUS_SUCCESS;
    }
    return status;
}

/**
 * Unblocks a wait block.
 *
 * \param WaitBlock A wait block.
 *
 * \remarks The wait block is in an undefined state after it is
 * unblocked. Do not attempt to read any values from it. All relevant
 * information should be saved before unblocking the wait block.
 */
__mayRaise FORCEINLINE VOID LOCK_pUnblockQueuedWaitBlock
(
    __inout PLOCK_QUEUED_WAIT_BLOCK WaitBlock
)
{
    NTSTATUS status;
    if (!_interlockedbittestandreset((PLONG)&WaitBlock->Flags, LOCK_QUEUED_WAITER_SPINNING_SHIFT))
    {
        status = NtReleaseKeyedEvent(LOCK_QueuedLockKeyedEventHandle,WaitBlock,FALSE,NULL);
        if (!NT_SUCCESS(status))
        {
            // Again.
            status = NtReleaseKeyedEvent(LOCK_QueuedLockKeyedEventHandle,WaitBlock,FALSE,NULL);
            if (!NT_SUCCESS(status))
            {
                LOCK_RaiseStatus(status);
            }
        }
    }
}

/**
 * Optimizes a queued lock waiters list.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 * \param IgnoreOwned TRUE to ignore lock state, FALSE
 * to conduct normal checks.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS, \ref LOCK_QUEUED_LOCK_TRAVERSING.
 */
FORCEINLINE VOID LOCK_pOptimizeQueuedLockListEx
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value,
    __in BOOLEAN IgnoreOwned
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    PLOCK_QUEUED_WAIT_BLOCK firstWaitBlock;
    PLOCK_QUEUED_WAIT_BLOCK lastWaitBlock;
    PLOCK_QUEUED_WAIT_BLOCK previousWaitBlock;
    value = Value;
    while (TRUE)
    {
        assert(value & LOCK_QUEUED_LOCK_TRAVERSING);
        if (!IgnoreOwned && !(value & LOCK_QUEUED_LOCK_OWNED))
        {
            // Someone has requested that we wake waiters.
            LOCK_pfWakeQueuedLock(QueuedLock, value);
            break;
        }
        // Perform the optimization.
        waitBlock = LOCK_GetQueuedLockWaitBlock(value);
        firstWaitBlock = waitBlock;
        while (TRUE)
        {
            lastWaitBlock = waitBlock->Last;
            if (lastWaitBlock)
            {
                // Save a pointer to the last wait block in
                // the first wait block and stop optimizing.
                //
                // We don't need to continue setting Previous
                // pointers because the last optimization run
                // would have set them already.
                firstWaitBlock->Last = lastWaitBlock;
                break;
            }
            previousWaitBlock = waitBlock;
            waitBlock = waitBlock->Next;
            waitBlock->Previous = previousWaitBlock;
        }
        // Try to clear the traversing bit.
        newValue = value - LOCK_QUEUED_LOCK_TRAVERSING;
        if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
        {
            break;
        }
        // Either someone pushed a wait block onto the list
        // or someone released ownership. In either case we
        // need to go back.
        value = newValue;
    }
}

/**
 * Optimizes a queued lock waiters list.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS, \ref LOCK_QUEUED_LOCK_TRAVERSING.
 */
VOID __fastcall LOCK_pfOptimizeQueuedLockList
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value
)
{
    LOCK_pOptimizeQueuedLockListEx(QueuedLock, Value, FALSE);
}

/**
 * Dequeues the appropriate number of wait blocks in
 * a queued lock.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 * \param IgnoreOwned TRUE to ignore lock state, FALSE
 * to conduct normal checks.
 * \param WakeAll TRUE to remove all wait blocks, FALSE
 * to decide based on the wait block type.
 */
FORCEINLINE PLOCK_QUEUED_WAIT_BLOCK LOCK_pPrepareToWakeQueuedLock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value,
    __in BOOLEAN IgnoreOwned,
    __in BOOLEAN WakeAll
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    PLOCK_QUEUED_WAIT_BLOCK firstWaitBlock;
    PLOCK_QUEUED_WAIT_BLOCK lastWaitBlock;
    PLOCK_QUEUED_WAIT_BLOCK previousWaitBlock;
    value = Value;
    while (TRUE)
    {
        // If there are multiple shared owners, no one is going
        // to wake waiters since the lock would still be owned.
        // Also if there are multiple shared owners they may be
        // traversing the list. While that is safe when
        // done concurrently with list optimization, we may be
        // removing and waking waiters.
        assert(!(value & LOCK_QUEUED_LOCK_MULTIPLE_SHARED));
        assert(IgnoreOwned || (value & LOCK_QUEUED_LOCK_TRAVERSING));
        // There's no point in waking a waiter if the lock
        // is owned. Clear the traversing bit.
        while (!IgnoreOwned && (value & LOCK_QUEUED_LOCK_OWNED))
        {
            newValue = value - LOCK_QUEUED_LOCK_TRAVERSING;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                return NULL;
            }
            value = newValue;
        }
        // Finish up any needed optimization (setting the
        // Previous pointers) while finding the last wait
        // block.
        waitBlock = LOCK_GetQueuedLockWaitBlock(value);
        firstWaitBlock = waitBlock;
        while (TRUE)
        {
            lastWaitBlock = waitBlock->Last;
            if (lastWaitBlock)
            {
                waitBlock = lastWaitBlock;
                break;
            }
            previousWaitBlock = waitBlock;
            waitBlock = waitBlock->Next;
            waitBlock->Previous = previousWaitBlock;
        }
        // Unlink the relevant wait blocks and clear the
        // traversing bit before we wake waiters.
        if (!WakeAll && (waitBlock->Flags & LOCK_QUEUED_WAITER_EXCLUSIVE) && (previousWaitBlock = waitBlock->Previous))
        {
            // We have an exclusive waiter and there are
            // multiple waiters.
            // We'll only be waking this waiter.
            // Unlink the wait block from the list.
            // Although other wait blocks may have their
            // Last pointers set to this wait block,
            // the algorithm to find the last wait block
            // will stop here. Likewise the Next pointers
            // are never followed beyond this point, so
            // we don't need to clear those.
            firstWaitBlock->Last = previousWaitBlock;
            // Make sure we only wake this waiter.
            waitBlock->Previous = NULL;
            if (!IgnoreOwned)
            {
                // Clear the traversing bit.
                _InterlockedExchangeAddPointer((PLONG_PTR)&QueuedLock->Value, -(LONG_PTR)LOCK_QUEUED_LOCK_TRAVERSING);
            }
            break;
        }
        else
        {
            // We're waking an exclusive waiter and there
            // is only one waiter, or we are waking
            // a shared waiter and possibly others.
            newValue = 0;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                break;
            }
            // Someone changed the lock (acquired it or
            // pushed a wait block).
            value = newValue;
        }
    }
    return waitBlock;
}

/**
 * Wakes waiters in a queued lock.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS, \ref LOCK_QUEUED_LOCK_TRAVERSING.
 * The function assumes the following flags are not set:
 * \ref LOCK_QUEUED_LOCK_MULTIPLE_SHARED.
 */
VOID __fastcall LOCK_pfWakeQueuedLock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value
)
{
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    PLOCK_QUEUED_WAIT_BLOCK previousWaitBlock;
    waitBlock = LOCK_pPrepareToWakeQueuedLock(QueuedLock, Value, FALSE, FALSE);
    // Wake waiters.
    while (waitBlock)
    {
        previousWaitBlock = waitBlock->Previous;
        LOCK_pUnblockQueuedWaitBlock(waitBlock);
        waitBlock = previousWaitBlock;
    }
}

/**
 * Wakes waiters in a queued lock.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 * \param IgnoreOwned TRUE to ignore lock state, FALSE
 * to conduct normal checks.
 * \param WakeAll TRUE to wake all waiters, FALSE to
 * decide based on the wait block type.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS, \ref LOCK_QUEUED_LOCK_TRAVERSING.
 * The function assumes the following flags are not set:
 * \ref LOCK_QUEUED_LOCK_MULTIPLE_SHARED.
 */
VOID __fastcall LOCK_pfWakeQueuedLockEx
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value,
    __in BOOLEAN IgnoreOwned,
    __in BOOLEAN WakeAll
)
{
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    PLOCK_QUEUED_WAIT_BLOCK previousWaitBlock;
    waitBlock = LOCK_pPrepareToWakeQueuedLock(QueuedLock, Value, IgnoreOwned, WakeAll);
    // Wake waiters.
    while (waitBlock)
    {
        previousWaitBlock = waitBlock->Previous;
        LOCK_pUnblockQueuedWaitBlock(waitBlock);
        waitBlock = previousWaitBlock;
    }
}

/**
 * Acquires a queued lock in exclusive mode.
 *
 * \param QueuedLock A queued lock.
 */
VOID __fastcall LOCK_fAcquireQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    ULONG_PTR currentValue;
    BOOLEAN optimize;
    LOCK_QUEUED_WAIT_BLOCK waitBlock;
    value = QueuedLock->Value;
    while (TRUE)
    {
        if (!(value & LOCK_QUEUED_LOCK_OWNED))
        {
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)(value + LOCK_QUEUED_LOCK_OWNED),(PVOID)value)) == value)
            {
                break;
            }
        }
        else
        {
            if (LOCK_pPushQueuedWaitBlock(QueuedLock,value,TRUE,&waitBlock,&optimize,&newValue,&currentValue))
            {
                if (optimize)
                {
                    LOCK_pfOptimizeQueuedLockList(QueuedLock, currentValue);
                }
                LOCK_pBlockOnQueuedWaitBlock(&waitBlock, TRUE, NULL);
            }
        }
        value = newValue;
    }
}

/**
 * Acquires a queued lock in shared mode.
 *
 * \param QueuedLock A queued lock.
 */
VOID __fastcall LOCK_fAcquireQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    ULONG_PTR currentValue;
    BOOLEAN optimize;
    LOCK_QUEUED_WAIT_BLOCK waitBlock;
    value = QueuedLock->Value;
    while (TRUE)
    {
        // We can't acquire if there are waiters for two reasons:
        //
        // We want to prioritize exclusive acquires over shared acquires.
        // There's currently no fast, safe way of finding the last wait
        // block and incrementing the shared owners count here.
        if (!(value & LOCK_QUEUED_LOCK_WAITERS) && (!(value & LOCK_QUEUED_LOCK_OWNED) || (LOCK_GetQueuedLockSharedOwners(value) > 0)))
        {
            newValue = (value + LOCK_QUEUED_LOCK_SHARED_INC) | LOCK_QUEUED_LOCK_OWNED;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                break;
            }
        }
        else
        {
            if (LOCK_pPushQueuedWaitBlock(QueuedLock,value,FALSE,&waitBlock,&optimize,&newValue,&currentValue))
            {
                if (optimize)
                {
                    LOCK_pfOptimizeQueuedLockList(QueuedLock, currentValue);
                }
                LOCK_pBlockOnQueuedWaitBlock(&waitBlock, TRUE, NULL);
            }
        }
        value = newValue;
    }
}

/**
 * Releases a queued lock in exclusive mode.
 *
 * \param QueuedLock A queued lock.
 */
VOID __fastcall LOCK_fReleaseQueuedLockExclusive
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    ULONG_PTR currentValue;
    value = QueuedLock->Value;
    while (TRUE)
    {
        assert(value & LOCK_QUEUED_LOCK_OWNED);
        assert((value & LOCK_QUEUED_LOCK_WAITERS) || (LOCK_GetQueuedLockSharedOwners(value) == 0));
        if ((value & (LOCK_QUEUED_LOCK_WAITERS | LOCK_QUEUED_LOCK_TRAVERSING)) != LOCK_QUEUED_LOCK_WAITERS)
        {
            // There are no waiters or someone is traversing the list.
            //
            // If there are no waiters, we're simply releasing ownership.
            // If someone is traversing the list, clearing the owned bit
            // is a signal for them to wake waiters.
            newValue = value - LOCK_QUEUED_LOCK_OWNED;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                break;
            }
        }
        else
        {
            // We need to wake waiters and no one is traversing the list.
            // Try to set the traversing bit and wake waiters.
            newValue = value - LOCK_QUEUED_LOCK_OWNED + LOCK_QUEUED_LOCK_TRAVERSING;
            currentValue = newValue;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                LOCK_pfWakeQueuedLock(QueuedLock, currentValue);
                break;
            }
        }
        value = newValue;
    }
}

/**
 * Releases a queued lock in shared mode.
 *
 * \param QueuedLock A queued lock.
 */
VOID __fastcall LOCK_fReleaseQueuedLockShared
(
    __inout PBLPP_QUEUED_LOCK QueuedLock
)
{
    ULONG_PTR value;
    ULONG_PTR newValue;
    ULONG_PTR currentValue;
    PLOCK_QUEUED_WAIT_BLOCK waitBlock;
    value = QueuedLock->Value;
    while (!(value & LOCK_QUEUED_LOCK_WAITERS))
    {
        assert(value & LOCK_QUEUED_LOCK_OWNED);
        assert((value & LOCK_QUEUED_LOCK_WAITERS) || (LOCK_GetQueuedLockSharedOwners(value) > 0));
        if (LOCK_GetQueuedLockSharedOwners(value) > 1)
        {
            newValue = value - LOCK_QUEUED_LOCK_SHARED_INC;
        }
        else
        {
            newValue = 0;
        }
        if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
        {
            return;
        }
        value = newValue;
    }
    if (value & LOCK_QUEUED_LOCK_MULTIPLE_SHARED)
    {
        // Unfortunately we have to find the last wait block and
        // decrement the shared owners count.
        waitBlock = LOCK_pFindLastQueuedWaitBlock(value);
        if ((ULONG)InterlockedDecrement((PLONG)&waitBlock->SharedOwners) > 0)
        {
            return;
        }
    }
    while (TRUE)
    {
        if (value & LOCK_QUEUED_LOCK_TRAVERSING)
        {
            newValue = value & ~(LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_MULTIPLE_SHARED);
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                break;
            }
        }
        else
        {
            newValue = (value & ~(LOCK_QUEUED_LOCK_OWNED | LOCK_QUEUED_LOCK_MULTIPLE_SHARED)) | LOCK_QUEUED_LOCK_TRAVERSING;
            currentValue = newValue;
            if ((newValue = (ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)value)) == value)
            {
                LOCK_pfWakeQueuedLock(QueuedLock, currentValue);
                break;
            }
        }
        value = newValue;
    }
}

/**
 * Wakes waiters in a queued lock for releasing it in exclusive mode.
 *
 * \param QueuedLock A queued lock.
 * \param Value The current value of the queued lock.
 *
 * \remarks The function assumes the following flags are set:
 * \ref LOCK_QUEUED_LOCK_WAITERS.
 * The function assumes the following flags are not set:
 * \ref LOCK_QUEUED_LOCK_MULTIPLE_SHARED, \ref LOCK_QUEUED_LOCK_TRAVERSING.
 */
VOID __fastcall LOCK_fWakeForReleaseQueuedLock
(
    __inout PBLPP_QUEUED_LOCK QueuedLock,
    __in ULONG_PTR Value
)
{
    ULONG_PTR newValue;
    newValue = Value + LOCK_QUEUED_LOCK_TRAVERSING;
    if ((ULONG_PTR)_InterlockedCompareExchangePointer((PPVOID)&QueuedLock->Value,(PVOID)newValue,(PVOID)Value) == Value)
    {
        LOCK_pfWakeQueuedLock(QueuedLock, newValue);
    }
}
