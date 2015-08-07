
#pragma once

#ifdef BASICLIBPP_EXPORTS
    #define BASIC_LIB_PP_API __declspec(dllexport)
#else
    #define BASIC_LIB_PP_API __declspec(dllimport)
#endif

#include "blpp_typedef.h"
#include <Windows.h>

#include "DisEng/decompose.h"
#include "lzma/lzma_shell.h"


//
// Internal info.
//

BASIC_LIB_PP_API T_Dword blpp_version();
BASIC_LIB_PP_API T_bool blpp_isInternalThread(T_Dword Tid);
BASIC_LIB_PP_API T_Dword blpp_getMemoryAllocationCount();

//
// Init once.
//

BASIC_LIB_PP_API T_bool blpp_initOnce(PT_void volatile *inited); // Return TRUE if not initialized.
BASIC_LIB_PP_API T_void blpp_initError(PT_void volatile *inited);

//
// Lock.
//

typedef struct DECLSPEC_ALIGN(8) _BLPP_QUEUED_LOCK
{
    ULONG_PTR Value;
} BLPP_QUEUED_LOCK, *PBLPP_QUEUED_LOCK;

#define BLPP_QUEUED_LOCK_INIT { 0 }

BASIC_LIB_PP_API T_void blpp_Lock_InitializeQueuedLock(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_void blpp_Lock_AcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_bool blpp_Lock_TryAcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_void blpp_Lock_ReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_void blpp_Lock_AcquireQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_void blpp_Lock_ReleaseQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_void blpp_Lock_AcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
BASIC_LIB_PP_API T_bool blpp_Lock_TryAcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);

class blpp_Lock_AutoQueuedLock
{
private:
    BLPP_QUEUED_LOCK &m_lock;
    bool m_bExclusive;
public:
    blpp_Lock_AutoQueuedLock(BLPP_QUEUED_LOCK &lock,bool bExclusive=false):m_lock(lock),m_bExclusive(bExclusive)
    {
        if (m_bExclusive)
        {
            blpp_Lock_AcquireQueuedLockExclusive(&m_lock);
        }
        else
        {
            blpp_Lock_AcquireQueuedLockShared(&m_lock);
        }
    }
    ~blpp_Lock_AutoQueuedLock()
    {
        if (m_bExclusive)
        {
            blpp_Lock_ReleaseQueuedLockExclusive(&m_lock);
        }
        else
        {
            blpp_Lock_ReleaseQueuedLockShared(&m_lock);
        }
    }
};

//
// Memory.
//

BASIC_LIB_PP_API PT_void blpp_mem_alloc(size_t size);
BASIC_LIB_PP_API PT_void blpp_mem_realloc(PT_void ptr,size_t newsize);
BASIC_LIB_PP_API T_void blpp_mem_free(PT_void ptr);

typedef struct _BLPP_FAST_ALLOCATOR_CONTEXT *PBLPP_FAST_ALLOCATOR_CONTEXT;
BASIC_LIB_PP_API PBLPP_FAST_ALLOCATOR_CONTEXT blpp_mem_createFastAllocator(T_Dword Size,T_Dword Depth); // Return the context of allocator.
BASIC_LIB_PP_API T_void blpp_mem_closeFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx);
BASIC_LIB_PP_API PT_void blpp_mem_allocateFromFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx);
BASIC_LIB_PP_API T_void blpp_mem_freeToFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx,PT_void Ptr);

//
// Hash.
//

BASIC_LIB_PP_API T_void blpp_Hash_MD5(PCT_void input,size_t ilen,T_byte output[16]);
BASIC_LIB_PP_API T_void blpp_Hash_SHA256(PCT_void input,size_t ilen,T_byte output[32],T_bool is224);

//
// Text encoder.
//

BASIC_LIB_PP_API T_bool blpp_TextEncode_AnsiToUnicode(PCT_str pszA, PT_wstr *ppszW); // Need free by blpp_mem_free.
BASIC_LIB_PP_API T_bool blpp_TextEncode_UnicodeToAnsi(PCT_wstr pszW,PT_str *ppszA); // Need free by blpp_mem_free.

//
// Sign verify.
//

typedef enum _BLPP_VERIFY_RESULT
{
    VrUnknown = 0,
    VrNoSignature,
    VrTrusted,
    VrExpired,
    VrRevoked,
    VrDistrust,
	VrSecuritySettings,
	VrBadSignature
} BLPP_VERIFY_RESULT, *PBLPP_VERIFY_RESULT;

BASIC_LIB_PP_API BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignW(PCT_wstr FileName);
BASIC_LIB_PP_API BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignA(PCT_str FileName);

//
// System info.
//

typedef enum _blpp_System_OSVersionEnum
{
    // Caution: If you add a new item here, update IsOSVersionAtLeast().
    WIN_UNKNOWN = 0,
    WIN_2000,
    WIN_XP,
    WIN_SERVER_2003,
    WIN_VISTA,
    WIN_7,
    WIN_8,
	WIN_8_1, // Windows BLUE
	WIN_10,
	WIN_NEW
} blpp_System_OSVersionEnum;

BASIC_LIB_PP_API blpp_System_OSVersionEnum blpp_System_GetCurrentOs();
BASIC_LIB_PP_API T_bool blpp_System_IsOsAtLeast(blpp_System_OSVersionEnum reqMinOS);
BASIC_LIB_PP_API T_bool blpp_System_Is64BitOs();
BASIC_LIB_PP_API T_bool blpp_System_EnableWow64FsRedirection(T_bool enable);
BASIC_LIB_PP_API T_bool blpp_System_RestartComputer();
BASIC_LIB_PP_API T_bool blpp_System_UpMyself();
BASIC_LIB_PP_API T_bool blpp_System_GetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType);
BASIC_LIB_PP_API T_bool blpp_System_GetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType);
BASIC_LIB_PP_API T_bool blpp_System_SetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type);
BASIC_LIB_PP_API T_bool blpp_System_SetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type);

//
// Object hack.
//

typedef enum _OBJ_OBJECT_TYPE
{
    OBJ_TYPE_Unknown = 0,
    OBJ_TYPE_Adapter,
    OBJ_TYPE_ALPC_Port,
    OBJ_TYPE_Callback,
    OBJ_TYPE_Controller,
    OBJ_TYPE_DebugObject,
    OBJ_TYPE_Desktop,
    OBJ_TYPE_Device,
    OBJ_TYPE_Directory,
    OBJ_TYPE_Driver,
    OBJ_TYPE_EtwConsumer,
    OBJ_TYPE_EtwRegistration,
    OBJ_TYPE_Event,
    OBJ_TYPE_EventPair,
    OBJ_TYPE_File,
    OBJ_TYPE_FilterCommunicationPort,
    OBJ_TYPE_FilterConnectionPort,
    OBJ_TYPE_IoCompletion,
    OBJ_TYPE_IoCompletionReserve,
    OBJ_TYPE_Job,
    OBJ_TYPE_Key,
    OBJ_TYPE_KeyedEvent,
    OBJ_TYPE_Mutant,
    OBJ_TYPE_PcwObject,
    OBJ_TYPE_PowerRequest,
    OBJ_TYPE_Process,
    OBJ_TYPE_Profile,
    OBJ_TYPE_Section,
    OBJ_TYPE_Semaphore,
    OBJ_TYPE_Session,
    OBJ_TYPE_SymbolicLink,
    OBJ_TYPE_Thread,
    OBJ_TYPE_Timer,
    OBJ_TYPE_TmEn,
    OBJ_TYPE_TmRm,
    OBJ_TYPE_TmTm,
    OBJ_TYPE_TmTx,
    OBJ_TYPE_Token,
    OBJ_TYPE_TpWorkerFactory,
    OBJ_TYPE_Type,
    OBJ_TYPE_UserApcReserve,
    OBJ_TYPE_WindowStation,
    OBJ_TYPE_WmiGuid,
    OBJ_TYPE_ALL_COUNT
} OBJ_OBJECT_TYPE;

BASIC_LIB_PP_API T_void blpp_Object_RefreshPrefix();
BASIC_LIB_PP_API T_bool blpp_Object_GetFormattedFileName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize);
BASIC_LIB_PP_API T_bool blpp_Object_GetFormattedKeyName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize);
BASIC_LIB_PP_API T_bool blpp_Object_QueryHandleInfo(HANDLE Handle,OBJ_OBJECT_TYPE *ObjType,PT_Dword refCount,PT_wstr nameOut,T_Dword outSize,PT_Dword PID,PT_Dword TID);

//
// MD5 database.
//

BASIC_LIB_PP_API PT_void blpp_md5Tree_New();
BASIC_LIB_PP_API T_void blpp_md5Tree_Delete(PT_void tree);
BASIC_LIB_PP_API T_status blpp_md5Tree_Insert(PT_void tree,T_byte md5[16],PCT_void data,T_Dword length);
BASIC_LIB_PP_API T_status blpp_md5Tree_Erase(PT_void tree,T_byte md5[16]);
BASIC_LIB_PP_API T_status blpp_md5Tree_Find(PT_void tree,T_byte md5[16],PT_void dataOut,PT_Dword dataLength);
BASIC_LIB_PP_API T_status blpp_md5Tree_Clear(PT_void tree);
BASIC_LIB_PP_API T_status blpp_md5Tree_LoadA(PT_void tree,PCT_str dbPath);
BASIC_LIB_PP_API T_status blpp_md5Tree_LoadW(PT_void tree,PCT_wstr dbPath);
BASIC_LIB_PP_API T_status blpp_md5Tree_SaveA(PT_void tree,PCT_str dbPath);
BASIC_LIB_PP_API T_status blpp_md5Tree_SaveW(PT_void tree,PCT_wstr dbPath);

//
// sqlite3
//

BASIC_LIB_PP_API PT_void blpp_sqlite_OpenDB(PCT_str szPath,T_bool bCreate,T_bool bWrite,PCT_str *errString);
BASIC_LIB_PP_API T_void blpp_sqlite_CloseDB(PT_void db);
typedef int (__cdecl * __pfn_blpp_sqlite_callback)(void* lparam,int argc,char** value,char** argv);
BASIC_LIB_PP_API T_bool blpp_sqlite_Exec(PT_void db,PCT_str sql,__pfn_blpp_sqlite_callback callback,PT_void lparam,PT_str errStringBuffer,T_Dword bufferLength);

//
// Disasm Engine
//

typedef struct _ZZY_DIS_CONTEXT *PZZY_DIS_CONTEXT;
BASIC_LIB_PP_API PZZY_DIS_CONTEXT DisEng_AllocateContext();
BASIC_LIB_PP_API T_void DisEng_FreeContext(PZZY_DIS_CONTEXT pContext);
BASIC_LIB_PP_API T_void DisEng_SetCpuType(PZZY_DIS_CONTEXT pContext,int n/*16,32,64*/);
BASIC_LIB_PP_API int DisEng_Disasm(PZZY_DIS_CONTEXT pContext,T_Qword base,T_Qword ip,PCT_void data,PT_str strBuffer,PDisEng_DECOMPOSED pDecomposed);

//
// Hook Library
//

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

BASIC_LIB_PP_API T_void blpp_Hook_FlushMemory();

BASIC_LIB_PP_API T_bool blpp_Hook_AddThread(T_Dword TID); // Auto called at DllMain.(If LoadLibrary you should add existing threads.)
BASIC_LIB_PP_API T_bool blpp_Hook_RemoveThread(T_Dword TID); // Auto called at DllMain.
BASIC_LIB_PP_API T_bool blpp_Hook_RefreshThread();
BASIC_LIB_PP_API T_bool blpp_Hook_AddAllThread();

// Caution: If hook not removed,free BLPP lib will cause crash!
BASIC_LIB_PP_API T_status blpp_Hook_SetBypassFilter(PT_void Target,__pfn_blpp_Hook_BypassCallBack pCallBack,PT_void Param,PT_void *pCookie,T_bool bReplace);
BASIC_LIB_PP_API T_bool blpp_Hook_RemoveBypassFilter(PT_void Cookie);
BASIC_LIB_PP_API T_bool blpp_Hook_StartBypassFilter(PT_void Cookie);
BASIC_LIB_PP_API T_bool blpp_Hook_StopBypassFilter(PT_void Cookie);

BASIC_LIB_PP_API T_status blpp_Hook_SetDirectFilter(PT_void Target,PT_void Filter,PT_void *JumpBack,PT_void *pCookie);
BASIC_LIB_PP_API T_bool blpp_Hook_RemoveDirectFilter(PT_void Cookie);
BASIC_LIB_PP_API T_bool blpp_Hook_StartDirectFilter(PT_void Cookie);
BASIC_LIB_PP_API T_bool blpp_Hook_StopDirectFilter(PT_void Cookie);

BASIC_LIB_PP_API T_bool blpp_Hook_FixHook(PT_Dword pCount);
BASIC_LIB_PP_API T_bool blpp_Hook_IsHookContext(PT_void Ptr,T_address Length);

BASIC_LIB_PP_API PT_void blpp_Hook_AllocSmartCallBackCode(PT_void Param,__pfn_blpp_Hook_SmartCallBack pCallBack,PT_void JumpBack);
BASIC_LIB_PP_API T_void blpp_Hook_FreeSmartCallBackCode(PT_void pCode);

//
// Thread Local Slot
//

BASIC_LIB_PP_API T_bool blpp_Tls_FlagOn(T_address Flag);
BASIC_LIB_PP_API T_bool blpp_Tls_SetFlag(T_address Flag);
BASIC_LIB_PP_API T_bool blpp_Tls_ClearFlag(T_address Flag);
BASIC_LIB_PP_API T_bool blpp_Tls_CheckAndSetFlag(T_address Flag); // If flag is on,return FALSE.

//
// Tray
//

typedef struct _BLPP_TRAY_CONTEXT *PBLPP_TRAY_CONTEXT;
BASIC_LIB_PP_API T_bool blpp_Tray_ChangeIcon(PBLPP_TRAY_CONTEXT pCtx,HICON hIcon);
BASIC_LIB_PP_API T_bool blpp_Tray_BalloonMessage(PBLPP_TRAY_CONTEXT pCtx,PCT_str szMsg,PCT_str szTitle);
BASIC_LIB_PP_API PBLPP_TRAY_CONTEXT blpp_Tray_CreateNewTray(HICON hIcon,HWND hWnd,UINT Message,PCT_str szTip,UINT Id);
BASIC_LIB_PP_API T_bool blpp_Tray_DestoryTray(PBLPP_TRAY_CONTEXT pCtx);

//
// Pipe
//

BASIC_LIB_PP_API T_bool blpp_Pipe_CreateLinker(PHANDLE hRead,PHANDLE hWrite);
BASIC_LIB_PP_API HANDLE blpp_Pipe_CreateNamedLinker(PCT_str LinkerName,T_bool WithLowestSecurity);
BASIC_LIB_PP_API T_bool blpp_Pipe_Accept(HANDLE hConn);
BASIC_LIB_PP_API T_bool blpp_Pipe_Disconnect(HANDLE hConn);
BASIC_LIB_PP_API T_bool blpp_Pipe_WaitServerOk(PCT_str LinkerName,T_Dword nTimeOut);
BASIC_LIB_PP_API HANDLE blpp_Pipe_Connect(PCT_str LinkerName,T_bool WithLowestSecurity);
BASIC_LIB_PP_API T_Dword blpp_Pipe_Send(HANDLE hConn,PCT_void Data,T_Dword Length);
BASIC_LIB_PP_API T_Dword blpp_Pipe_Recv(HANDLE hConn,PT_void Data,T_Dword Length);
inline T_void blpp_Pipe_FreePipe(HANDLE hConn)
{
    CloseHandle(hConn);
}

//
// Payload
//

BASIC_LIB_PP_API PT_void blpp_Payload_FindNativePack(PCT_str Identity,PT_Dword DataLength);
BASIC_LIB_PP_API PT_void blpp_Payload_AddNativePack(PCT_str Identity,PCT_void Data,T_Dword DataLength);
BASIC_LIB_PP_API T_bool blpp_Payload_FreeNativePack(PT_void pData);
BASIC_LIB_PP_API PT_void blpp_Payload_FindRemotePack(HANDLE hProcess,PCT_str Identity,PT_Dword DataLength);
BASIC_LIB_PP_API PT_void blpp_Payload_AddRemotePack(HANDLE hProcess,PCT_str Identity,PCT_void pData,T_Dword DataLength);
BASIC_LIB_PP_API T_bool blpp_Payload_FreeRemotePack(HANDLE hProcess,PT_void pData);

//
// Debug log.
//

BASIC_LIB_PP_API T_bool blpp_Log_SetLogDirectory(PCT_str szPath);
BASIC_LIB_PP_API T_void blpp_Log_DebugLog(PCT_str Target,...);

//
// File system bypass function(s)
//

BASIC_LIB_PP_API HANDLE blpp_fs_CreateFileBypassA(PCT_str lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes);
BASIC_LIB_PP_API HANDLE blpp_fs_CreateFileBypassW(PCT_wstr lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes);
BASIC_LIB_PP_API T_bool blpp_fs_CreateDirectoryBypassA(PCT_str lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BASIC_LIB_PP_API T_bool blpp_fs_CreateDirectoryBypassW(PCT_wstr lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BASIC_LIB_PP_API T_bool blpp_fs_RemoveDirectoryBypassA(PCT_str lpPathName);
BASIC_LIB_PP_API T_bool blpp_fs_RemoveDirectoryBypassW(PCT_wstr lpPathName);
BASIC_LIB_PP_API T_bool blpp_fs_DeleteFileBypassA(PCT_str lpFileName);
BASIC_LIB_PP_API T_bool blpp_fs_DeleteFileBypassW(PCT_wstr lpFileName);
BASIC_LIB_PP_API T_bool blpp_fs_MoveFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName);
BASIC_LIB_PP_API T_bool blpp_fs_MoveFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName);
BASIC_LIB_PP_API T_bool blpp_fs_CopyFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName,T_bool bFailIfExists);
BASIC_LIB_PP_API T_bool blpp_fs_CopyFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName,T_bool bFailIfExists);
BASIC_LIB_PP_API T_bool blpp_fs_GetFileAttributesBypassA(PT_str lpPathName,PDWORD pAttr);
BASIC_LIB_PP_API T_bool blpp_fs_GetFileAttributesBypassW(PT_wstr lpPathName,PDWORD pAttr);
BASIC_LIB_PP_API T_bool blpp_fs_SetFileAttributesBypassA(PT_str lpPathName,DWORD dwAttr);
BASIC_LIB_PP_API T_bool blpp_fs_SetFileAttributesBypassW(PT_wstr lpPathName,DWORD dwAttr);

#if defined(_WIN64)
    #include <PshPack8.h>
#else
    #include <PshPack4.h>
#endif

typedef struct _BLPP_MAP_FILE_STRUCT
{
    HANDLE hFile;
    HANDLE hMapping;
    PT_void ImageBase;
    LARGE_INTEGER FileSize;
} BLPP_MAP_FILE_STRUCT,*PBLPP_MAP_FILE_STRUCT;

#include <PopPack.h>

BASIC_LIB_PP_API T_status blpp_fs_LoadFileAsMemoryA(PCT_str lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass);
BASIC_LIB_PP_API T_status blpp_fs_LoadFileAsMemoryW(PCT_wstr lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass);
BASIC_LIB_PP_API T_void blpp_fs_UnLoadFileMemory(PBLPP_MAP_FILE_STRUCT pMapFile);
