/************************************************************************/
/* Mini hook library                                                    */
/************************************************************************/

#ifndef _MINI_HOOK_H_INCLUDED_
#define _MINI_HOOK_H_INCLUDED_

/************************************************************************/

#include "../blpp_typedef.h"

/************************************************************************/

typedef struct _MEM_MANAGER // Memory must with Read/Write/Execute
{
    void * (* alloc)(void * const userdata, const size_t size);
    void (* free)(void * const userdata, void *p);
    void *userdata;
} MEM_MANAGER, *PMEM_MANAGER;

typedef enum _HOOK_STATUS
{
    HOOK_STATUS_SUCCESS = 0,
    HOOK_STATUS_FAILED,
    HOOK_STATUS_MEMORY_DENIED,
    HOOK_STATUS_INSUFFICIENT_MEMORY,
    HOOK_STATUS_ALREADY_HOOKED,
} HOOK_STATUS;

typedef struct _HOOK_CONTEXT *PHOOK_CONTEXT;

/************************************************************************/

PHOOK_CONTEXT Hook_New(PMEM_MANAGER mem_mgr);
T_bool Hook_Delete(PHOOK_CONTEXT pCtx);
T_void Hook_FlushMemory(PHOOK_CONTEXT pCtx);

T_bool HOOK_AddThread(PHOOK_CONTEXT pCtx,T_Dword TID);
T_bool HOOK_RemoveThread(PHOOK_CONTEXT pCtx,T_Dword TID);
T_bool HOOK_SetAllThreadAlive(PHOOK_CONTEXT pCtx);

HOOK_STATUS Hook_DetourAttach(PHOOK_CONTEXT pCtx,PT_void Target,PT_void To,PT_void *pCookie,PT_void *pJumpBack);
HOOK_STATUS Hook_DetourDetach(PHOOK_CONTEXT pCtx,PT_void Cookie);

T_bool Hook_StartFilter(PHOOK_CONTEXT pCtx,PT_void Cookie);
T_bool Hook_StopFilter(PHOOK_CONTEXT pCtx,PT_void Cookie);

T_bool Hook_FixDetour(PHOOK_CONTEXT pCtx,PT_Dword pFixedCount);
T_bool Hook_IsDetourContextMemory(PHOOK_CONTEXT pCtx,PT_void pStart,T_address Length);

/************************************************************************/

#endif // _MINI_HOOK_H_INCLUDED_
