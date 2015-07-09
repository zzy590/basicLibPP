//////////////////////////////////////////////////////////////////////////
// Basic Function Header


#pragma once


//////////////////////////////////////////////////////////////////////////


//
// Base type
//

#include "blpp_config.h"
#include <assert.h>

#include <Windows.h>
#include <ShlObj.h>

#include "QueuedLock/QueuedLock.h"
#include "memlib/_malloc.h"
#include "lzma/lzma_shell.h"
#include "HandleInfo/HndInfo.h"
#include "sqlite/sqlite3.h"
#include "DisEng/dis_out.h"
#include "GeneralHook/hook_mgr.h"

#include <set>
#include <iostream>

using namespace std;


//////////////////////////////////////////////////////////////////////////


#define VERSION_ZZY ((T_Dword)1000100)

#ifdef Config_DBG
    #define DBG_PRINT(_x) cout<<_x<<endl;
    #define DBG_SHOW_WSTRING(_uni) {PT_str m_ansi;if (blpp_TextEncode_UnicodeToAnsi((PT_wstr)(_uni),&m_ansi)){cout<<m_ansi<<endl;blpp_mem_free(m_ansi);}}
#else
    #define DBG_PRINT(_x)
    #define DBG_SHOW_WSTRING(_uni)
#endif


//////////////////////////////////////////////////////////////////////////


extern set<T_Dword> blpp_internalThreadSet;
extern BLPP_QUEUED_LOCK blpp_internalThreadSetLock;


//////////////////////////////////////////////////////////////////////////


bool blpp_init();
void blpp_uninit();

void * tmpMemAlloc(void *p,size_t size);
void tmpMemFree(void *p,void *address);

T_Dword blpp_version();
T_bool blpp_isInternalThread(T_Dword Tid);

T_bool blpp_initOnce(PT_void volatile *inited); // Return TRUE if not initialized.
T_void blpp_initError(PT_void volatile *inited);

class AutoQueuedLock
{
private:
    BLPP_QUEUED_LOCK &m_lock;
    bool m_bExclusive;
public:
    AutoQueuedLock(BLPP_QUEUED_LOCK &lock,bool bExclusive=false):m_lock(lock),m_bExclusive(bExclusive)
    {
        if (m_bExclusive)
        {
            LOCK_AcquireQueuedLockExclusive(&m_lock);
        }
        else
        {
            LOCK_AcquireQueuedLockShared(&m_lock);
        }
    }
    ~AutoQueuedLock()
    {
        if (m_bExclusive)
        {
            LOCK_ReleaseQueuedLockExclusive(&m_lock);
        }
        else
        {
            LOCK_ReleaseQueuedLockShared(&m_lock);
        }
    }
};

T_void blpp_Lock_InitializeQueuedLock(PBLPP_QUEUED_LOCK QueuedLock);
T_void blpp_Lock_AcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
T_bool blpp_Lock_TryAcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
T_void blpp_Lock_ReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
T_void blpp_Lock_AcquireQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock);
T_void blpp_Lock_ReleaseQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock);
T_void blpp_Lock_AcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);
T_bool blpp_Lock_TryAcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock);

PT_void blpp_mem_alloc(size_t size);
PT_void blpp_mem_realloc(PT_void ptr,size_t newsize);
T_void blpp_mem_free(PT_void ptr);

typedef struct _BLPP_FAST_ALLOCATOR_CONTEXT *PBLPP_FAST_ALLOCATOR_CONTEXT;
PBLPP_FAST_ALLOCATOR_CONTEXT blpp_mem_createFastAllocator(T_Dword Size,T_Dword Depth); // Return the context of allocator.
T_void blpp_mem_closeFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx);
PT_void blpp_mem_allocateFromFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx);
T_void blpp_mem_freeToFastAllocator(PBLPP_FAST_ALLOCATOR_CONTEXT pCtx,PT_void Ptr);

T_void blpp_Hash_MD5(PCT_void input,size_t ilen,T_byte output[16]);
T_void blpp_Hash_SHA256(PCT_void input,size_t ilen,T_byte output[32],T_bool is224);

T_bool blpp_TextEncode_AnsiToUnicode(PCT_str pszA, PT_wstr *ppszW); // Need free by blpp_mem_free.
T_bool blpp_TextEncode_UnicodeToAnsi(PCT_wstr pszW,PT_str *ppszA); // Need free by blpp_mem_free.

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

BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignW(PCT_wstr FileName);
BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignA(PCT_str FileName);

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

blpp_System_OSVersionEnum blpp_System_GetCurrentOs();
T_bool blpp_System_IsOsAtLeast(blpp_System_OSVersionEnum reqMinOS);
T_bool blpp_System_Is64BitOs();
T_bool blpp_System_EnableWow64FsRedirection(T_bool enable);
T_bool blpp_System_RestartComputer();
T_bool blpp_System_UpMyself();
T_bool blpp_System_GetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType);
T_bool blpp_System_GetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType);
T_bool blpp_System_SetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type);
T_bool blpp_System_SetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type);

T_void blpp_Object_RefreshPrefix();
T_bool blpp_Object_GetFormattedFileName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize);
T_bool blpp_Object_GetFormattedKeyName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize);
T_bool blpp_Object_QueryHandleInfo(HANDLE Handle,OBJ_OBJECT_TYPE *ObjType,PT_Dword refCount,PT_wstr nameOut,T_Dword outSize,PT_Dword PID,PT_Dword TID);

PT_void blpp_md5Tree_New();
T_void blpp_md5Tree_Delete(PT_void tree);
T_status blpp_md5Tree_Insert(PT_void tree,T_byte md5[16],PCT_void data,T_Dword length);
T_status blpp_md5Tree_Erase(PT_void tree,T_byte md5[16]);
T_status blpp_md5Tree_Find(PT_void tree,T_byte md5[16],PT_void dataOut,PT_Dword dataLength);
T_status blpp_md5Tree_Clear(PT_void tree);
T_status blpp_md5Tree_LoadA(PT_void tree,PCT_str dbPath);
T_status blpp_md5Tree_LoadW(PT_void tree,PCT_wstr dbPath);
T_status blpp_md5Tree_SaveA(PT_void tree,PCT_str dbPath);
T_status blpp_md5Tree_SaveW(PT_void tree,PCT_wstr dbPath);

PT_void blpp_sqlite_OpenDB(PCT_str szPath,T_bool bCreate,T_bool bWrite,PCT_str *errString);
T_void blpp_sqlite_CloseDB(PT_void db);
typedef int (__cdecl * __pfn_blpp_sqlite_callback)(void* lparam,int argc,char** value,char** argv);
T_bool blpp_sqlite_Exec(PT_void db,PCT_str sql,__pfn_blpp_sqlite_callback callback,PT_void lparam,PT_str errStringBuffer,T_Dword bufferLength);

T_Dword SelectTlsSlot();
T_void FreeSelectedTls(T_Dword tls);
T_bool IsThreadFlagOn(T_Dword Tls,T_address Flag);
T_bool SetThreadFlag(T_Dword Tls,T_address Flag);
T_bool ClearThreadFlag(T_Dword Tls,T_address Flag);
T_bool CheckAndSetThreadFlag(T_Dword Tls,T_address Flag); // If flag is on,return FALSE.

typedef struct _BLPP_TRAY_CONTEXT *PBLPP_TRAY_CONTEXT;
T_bool blpp_Tray_ChangeIcon(PBLPP_TRAY_CONTEXT pCtx,HICON hIcon);
T_bool blpp_Tray_BalloonMessage(PBLPP_TRAY_CONTEXT pCtx,PCT_str szMsg,PCT_str szTitle);
PBLPP_TRAY_CONTEXT blpp_Tray_CreateNewTray(HICON hIcon,HWND hWnd,UINT Message,PCT_str szTip,UINT Id);
T_bool blpp_Tray_DestoryTray(PBLPP_TRAY_CONTEXT pCtx);

T_bool blpp_Pipe_CreateLinker(PHANDLE hRead,PHANDLE hWrite);
HANDLE blpp_Pipe_CreateNamedLinker(PCT_str LinkerName,T_bool WithLowestSecurity);
T_bool blpp_Pipe_Accept(HANDLE hConn);
T_bool blpp_Pipe_Disconnect(HANDLE hConn);
T_bool blpp_Pipe_WaitServerOk(PCT_str LinkerName,T_Dword nTimeOut);
HANDLE blpp_Pipe_Connect(PCT_str LinkerName,T_bool WithLowestSecurity);
T_Dword blpp_Pipe_Send(HANDLE hConn,PCT_void Data,T_Dword Length);
T_Dword blpp_Pipe_Recv(HANDLE hConn,PT_void Data,T_Dword Length);
inline T_void blpp_Pipe_FreePipe(HANDLE hConn)
{
    CloseHandle(hConn);
}

PT_void blpp_Payload_FindNativePack(PCT_str Identity,PT_Dword DataLength);
PT_void blpp_Payload_AddNativePack(PCT_str Identity,PCT_void Data,T_Dword DataLength);
T_bool blpp_Payload_FreeNativePack(PT_void pData);
PT_void blpp_Payload_FindRemotePack(HANDLE hProcess,PCT_str Identity,PT_Dword DataLength);
PT_void blpp_Payload_AddRemotePack(HANDLE hProcess,PCT_str Identity,PCT_void pData,T_Dword DataLength);
T_bool blpp_Payload_FreeRemotePack(HANDLE hProcess,PT_void pData);

T_bool blpp_Log_SetLogDirectory(PCT_str szPath);
T_void blpp_Log_DebugLog(PCT_str Target,...);

HANDLE blpp_fs_CreateFileBypassA(PCT_str lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes);
HANDLE blpp_fs_CreateFileBypassW(PCT_wstr lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes);
T_bool blpp_fs_CreateDirectoryBypassA(PCT_str lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
T_bool blpp_fs_CreateDirectoryBypassW(PCT_wstr lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
T_bool blpp_fs_RemoveDirectoryBypassA(PCT_str lpPathName);
T_bool blpp_fs_RemoveDirectoryBypassW(PCT_wstr lpPathName);
T_bool blpp_fs_DeleteFileBypassA(PCT_str lpFileName);
T_bool blpp_fs_DeleteFileBypassW(PCT_wstr lpFileName);
T_bool blpp_fs_MoveFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName);
T_bool blpp_fs_MoveFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName);
T_bool blpp_fs_CopyFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName,T_bool bFailIfExists);
T_bool blpp_fs_CopyFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName,T_bool bFailIfExists);
T_bool blpp_fs_GetFileAttributesBypassA(PT_str lpPathName,PDWORD pAttr);
T_bool blpp_fs_GetFileAttributesBypassW(PT_wstr lpPathName,PDWORD pAttr);
T_bool blpp_fs_SetFileAttributesBypassA(PT_str lpPathName,DWORD dwAttr);
T_bool blpp_fs_SetFileAttributesBypassW(PT_wstr lpPathName,DWORD dwAttr);

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

T_status blpp_fs_LoadFileAsMemoryA(PCT_str lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass);
T_status blpp_fs_LoadFileAsMemoryW(PCT_wstr lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass);
T_void blpp_fs_UnLoadFileMemory(PBLPP_MAP_FILE_STRUCT pMapFile);
