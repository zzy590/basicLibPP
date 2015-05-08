//////////////////////////////////////////////////////////////////////////
//
// Hook manager
// Author: zzy
//
//////////////////////////////////////////////////////////////////////////


#ifndef _HOOK_MGR_H_INCLUDED_
#define _HOOK_MGR_H_INCLUDED_

#include "../basic_fun.h"


//////////////////////////////////////////////////////////////////////////


#if defined(_M_IX86)
    #include <PshPack4.h>
    typedef struct _BLPP_HOOK_INFO
    {
        T_Bit32u eFLAGS; // read only
        T_Bit32u edi;
        T_Bit32u esi;
        T_Bit32u ebp;
        T_Bit32u esp;
        T_Bit32u ebx;
        T_Bit32u edx;
        T_Bit32u ecx;
        T_Bit32u eax;
    } BLPP_HOOK_INFO, *PBLPP_HOOK_INFO;
    #include <PopPack.h>
#elif defined(_M_X64)
    #include <PshPack8.h>
    typedef struct _BLPP_HOOK_INFO
    {
        T_Bit64u rFLAGS; // read only
        T_Bit64u r15;
        T_Bit64u r14;
        T_Bit64u r13;
        T_Bit64u r12;
        T_Bit64u r11;
        T_Bit64u r10;
        T_Bit64u r9;
        T_Bit64u r8;
        T_Bit64u rdi;
        T_Bit64u rsi;
        T_Bit64u rbp;
        T_Bit64u rsp; // read only
        T_Bit64u rbx;
        T_Bit64u rdx;
        T_Bit64u rcx;
        T_Bit64u rax;
    } BLPP_HOOK_INFO, *PBLPP_HOOK_INFO;
    #include <PopPack.h>
#else
    #error "not support."
#endif

typedef T_void (__stdcall * __pfn_blpp_Hook_BypassCallBack)(PT_void Param,PBLPP_HOOK_INFO pInfo);
typedef PT_void (__stdcall * __pfn_blpp_Hook_SmartCallBack)(PT_void Param,PT_void eax_rax); // return to change eax/rax


//////////////////////////////////////////////////////////////////////////


T_bool blpp_Hook_AddThread(T_Dword TID);
T_bool blpp_Hook_RemoveThread(T_Dword TID);
T_bool blpp_Hook_RefreshThread();
T_bool blpp_Hook_AddAllThread();

T_status blpp_Hook_SetBypassFilter(PT_void Target,__pfn_blpp_Hook_BypassCallBack pCallBack,PT_void Param,PT_void *pCookie,T_bool bReplace);
T_bool blpp_Hook_RemoveBypassFilter(PT_void Cookie);
T_bool blpp_Hook_StartBypassFilter(PT_void Cookie);
T_bool blpp_Hook_StopBypassFilter(PT_void Cookie);

T_status blpp_Hook_SetDirectFilter(PT_void Target,PT_void Filter,PT_void *JumpBack,PT_void *pCookie);
T_bool blpp_Hook_RemoveDirectFilter(PT_void Cookie);
T_bool blpp_Hook_StartDirectFilter(PT_void Cookie);
T_bool blpp_Hook_StopDirectFilter(PT_void Cookie);

T_bool blpp_Hook_FixHook(PT_Dword pCount);
T_bool blpp_Hook_IsHookContext(PT_void Ptr,T_address Length);

PT_void blpp_Hook_AllocSmartCallBackCode(PT_void Param,__pfn_blpp_Hook_SmartCallBack pCallBack,PT_void JumpBack);
T_void blpp_Hook_FreeSmartCallBackCode(PT_void pCode);


//////////////////////////////////////////////////////////////////////////


#endif // _HOOK_MGR_H_INCLUDED_
