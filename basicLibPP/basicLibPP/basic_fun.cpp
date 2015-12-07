//////////////////////////////////////////////////////////////////////////
// Basic Function


#include "basic_fun.h"

#include <xstring>

using namespace std;


//////////////////////////////////////////////////////////////////////////


static mspace my_heap = NULL;

static T_Dword OsVersionMajor;
static T_Dword OsVersionMinor;

static T_Dword blpp_memoryAllocationCount = 0;
static BLPP_QUEUED_LOCK blpp_memoryAllocationCountLock = BLPP_QUEUED_LOCK_INIT;

set<T_Dword> blpp_internalThreadSet;
BLPP_QUEUED_LOCK blpp_internalThreadSetLock = BLPP_QUEUED_LOCK_INIT;

static T_Dword my_tls = TLS_OUT_OF_INDEXES;


//////////////////////////////////////////////////////////////////////////


bool blpp_init()
{
    // Get system info.
    OSVERSIONINFO Version;
    Version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&Version))
    {
        return false;
    }
    OsVersionMajor = Version.dwMajorVersion;
    OsVersionMinor = Version.dwMinorVersion;
    // Memory.
    if (NULL == (my_heap = create_mspace(0,1)))
    {
        return false;
    }
    // Lock.
    if (!LOCK_QueuedLockInitialization())
    {
        destroy_mspace(my_heap);
        my_heap = NULL;
        return false;
    }
    my_tls = SelectTlsSlot();
    if (TLS_OUT_OF_INDEXES == my_tls)
    {
        LOCK_QueuedLockUninitialization();
        destroy_mspace(my_heap);
        my_heap = NULL;
        return false;
    }
    return true;
}

void blpp_uninit()
{
    ObjUninit();
    FreeSelectedTls(my_tls);
    LOCK_QueuedLockUninitialization();
    destroy_mspace(my_heap);
    my_heap = NULL;
}


//
// Internal function.
//

void * tmpMemAlloc(void *p,size_t size)
{
    return blpp_mem_alloc(size);
}

void tmpMemFree(void *p,void *address)
{
    blpp_mem_free(address);
}


//
// Internal info.
//

T_Dword blpp_version()
{
    return VERSION_ZZY;
}

T_bool blpp_isInternalThread(T_Dword Tid)
{
    AutoQueuedLock al(blpp_internalThreadSetLock);
    return (blpp_internalThreadSet.find(Tid)!=blpp_internalThreadSet.end());
}

T_Dword blpp_getMemoryAllocationCount()
{
	AutoQueuedLock al(blpp_memoryAllocationCountLock);
	return blpp_memoryAllocationCount;
}


//
// Init once.
//

T_bool blpp_initOnce(PT_void volatile *inited) // Return TRUE if not initialized.
{
	if (_InterlockedBitTestAndSetPointer((LONG_PTR volatile *)inited, 0))
	{
		return FALSE;
	}
	return TRUE;
}

T_void blpp_initError(PT_void volatile *inited)
{
	_InterlockedExchangePointer(inited, 0);
}


//
// Lock.
//

T_void blpp_Lock_InitializeQueuedLock(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_InitializeQueuedLock(QueuedLock);
}

T_void blpp_Lock_AcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_AcquireQueuedLockExclusive(QueuedLock);
}

T_bool blpp_Lock_TryAcquireQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock)
{
    return LOCK_TryAcquireQueuedLockExclusive(QueuedLock);
}

T_void blpp_Lock_ReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_ReleaseQueuedLockExclusive(QueuedLock);
}

T_void blpp_Lock_AcquireQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_AcquireQueuedLockShared(QueuedLock);
}

T_void blpp_Lock_ReleaseQueuedLockShared(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_ReleaseQueuedLockShared(QueuedLock);
}

T_void blpp_Lock_AcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock)
{
    LOCK_AcquireReleaseQueuedLockExclusive(QueuedLock);
}

T_bool blpp_Lock_TryAcquireReleaseQueuedLockExclusive(PBLPP_QUEUED_LOCK QueuedLock)
{
    return LOCK_TryAcquireReleaseQueuedLockExclusive(QueuedLock);
}


//
// Memory.
//

PT_void blpp_mem_alloc(size_t size)
{
    void *ptr;
    ptr = mspace_malloc(my_heap,size);
    if (ptr != NULL)
    {
        ZeroMemory(ptr,size);
		LOCK_AcquireQueuedLockExclusive(&blpp_memoryAllocationCountLock);
		++blpp_memoryAllocationCount;
		LOCK_ReleaseQueuedLockExclusive(&blpp_memoryAllocationCountLock);
    }
    return ptr;
}

PT_void blpp_mem_realloc(PT_void ptr,size_t newsize)
{
    void *newPtr = mspace_realloc(my_heap,ptr,newsize);
	if (NULL == ptr && newPtr != NULL)
	{
		LOCK_AcquireQueuedLockExclusive(&blpp_memoryAllocationCountLock);
		++blpp_memoryAllocationCount;
		LOCK_ReleaseQueuedLockExclusive(&blpp_memoryAllocationCountLock);
	}
	else if (ptr != NULL && NULL == newPtr)
	{
		LOCK_AcquireQueuedLockExclusive(&blpp_memoryAllocationCountLock);
		--blpp_memoryAllocationCount;
		LOCK_ReleaseQueuedLockExclusive(&blpp_memoryAllocationCountLock);
	}
	return newPtr;
}

T_void blpp_mem_free(PT_void ptr)
{
    if (ptr)
    {
		mspace_free(my_heap, ptr);
		LOCK_AcquireQueuedLockExclusive(&blpp_memoryAllocationCountLock);
		--blpp_memoryAllocationCount;
		LOCK_ReleaseQueuedLockExclusive(&blpp_memoryAllocationCountLock);
    }
}


//
// Text encode.
//

T_bool blpp_TextEncode_AnsiToUnicode(PCT_str pszA, PT_wstr *ppszW) // Need free by blpp_mem_free.
{
    T_Dword cCharacters;
    if (NULL == pszA)
    {
        *ppszW = NULL;
        return FALSE;
    }
    cCharacters = (T_Dword)strlen(pszA)+1;
    *ppszW = (PT_wstr)blpp_mem_alloc(cCharacters*2);
    if (NULL == *ppszW)
    {
        return FALSE;
    }
    if (0 == MultiByteToWideChar(CP_ACP,0,pszA,cCharacters,*ppszW,cCharacters))
    {
        blpp_mem_free(*ppszW);
        *ppszW = NULL;
        return FALSE;
    }
    return TRUE;
}

T_bool blpp_TextEncode_UnicodeToAnsi(PCT_wstr pszW,PT_str *ppszA) // Need free by blpp_mem_free.
{
    T_Dword cbAnsi,cCharacters;
    if (NULL == pszW)
    {
        *ppszA = NULL;
        return FALSE;
    }
    cCharacters = (T_Dword)wcslen(pszW)+1;
    cbAnsi = cCharacters*2;
    *ppszA = (LPSTR)blpp_mem_alloc(cbAnsi);
    if (NULL == *ppszA)
    {
        return FALSE;
    }
    if (0 == WideCharToMultiByte(CP_ACP,0,pszW,cCharacters,*ppszA,cbAnsi,NULL,NULL))
    {
        blpp_mem_free(*ppszA);
        *ppszA = NULL;
        return FALSE;
    }
    return TRUE;
}


//
// System info.
//

blpp_System_OSVersionEnum blpp_System_GetCurrentOs()
{
    switch (OsVersionMajor)
    {
    case 5:
        switch (OsVersionMinor)
        {
        case 0:
            return WIN_2000;
        case 1:
            return WIN_XP;
        case 2:
            return WIN_SERVER_2003;
        default:
            return WIN_UNKNOWN;
        }
    case 6:
        switch (OsVersionMinor)
        {
        case 0:
            return WIN_VISTA;
        case 1:
            return WIN_7;
        case 2:
            return WIN_8;
		case 3:
			return WIN_8_1;
        default:
            return WIN_UNKNOWN;
        }
	case 10:
		switch (OsVersionMinor)
		{
		case 0:
			return WIN_10;
		default:
			return WIN_NEW;
		}
    default:
        break;
    }
    return WIN_UNKNOWN;
}

T_bool blpp_System_IsOsAtLeast(blpp_System_OSVersionEnum reqMinOS)
{
    T_Dword major = 0, minor = 0;
    switch (reqMinOS)
    {
    case WIN_2000:
        major = 5;
        minor = 0;
        break;
    case WIN_XP:
        major = 5;
        minor = 1;
        break;
    case WIN_SERVER_2003:
        major = 5;
        minor = 2;
        break;
    case WIN_VISTA:
        major = 6;
        minor = 0;
        break;
    case WIN_7:
        major = 6;
        minor = 1;
        break;
    case WIN_8:
        major = 6;
        minor = 2;
        break;
	case WIN_8_1:
		major = 6;
		minor = 3;
		break;
	case WIN_10:
		major = 10;
		minor = 0;
		break;
	case WIN_NEW:
		major = 10;
		minor = 1;
		break;
    default:
        break;
    }
    return ((OsVersionMajor << 16 | OsVersionMinor << 8) >= (major << 16 | minor << 8));
}

T_bool blpp_System_Is64BitOs()
{
#if defined(_WIN64)
    return TRUE;
#else
    static T_bool is64 = FALSE;
    static T_bool valid = FALSE;
    if (valid)
    {
        return is64;
    }
    BOOL isWow64 = FALSE;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS )(HANDLE hProcess,PBOOL Wow64Process);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");
    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&isWow64))
        {
            isWow64 = FALSE;
        }
    }
    valid = TRUE;
    is64 = (T_bool)isWow64;
    return is64;
#endif
}

T_bool blpp_System_EnableWow64FsRedirection(T_bool enable)
{
    typedef BOOLEAN (WINAPI *Wow64EnableWow64FsRedirection_t)(BOOL enable);
    Wow64EnableWow64FsRedirection_t wow64EnableWow64FsRedirection = (Wow64EnableWow64FsRedirection_t)GetProcAddress(GetModuleHandle("kernel32"),"Wow64EnableWow64FsRedirection");
    if (!wow64EnableWow64FsRedirection)
    {
        return FALSE;
    }
    return (T_bool)wow64EnableWow64FsRedirection((BOOL)enable);
}

T_bool blpp_System_RestartComputer()
{
    TOKEN_PRIVILEGES tokenPrivil;
    HANDLE hTkn;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&hTkn))
    {
        return FALSE;
    }
    LookupPrivilegeValue(NULL,SE_SHUTDOWN_NAME,&tokenPrivil.Privileges[0].Luid);
    tokenPrivil.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tokenPrivil.PrivilegeCount = 1;
    AdjustTokenPrivileges(hTkn,FALSE,&tokenPrivil,0,(PTOKEN_PRIVILEGES)NULL,0);
    if (ERROR_SUCCESS != GetLastError())
    {
        return FALSE;
    }
    if (!ExitWindowsEx(EWX_REBOOT,SHTDN_REASON_MAJOR_OTHER|SHTDN_REASON_MINOR_OTHER|SHTDN_REASON_FLAG_PLANNED))
    {
        return FALSE;
    }
    return TRUE;
}

T_bool blpp_System_UpMyself()
{
    if (!IsUserAnAdmin())
    {
        return FALSE;
    }
    HANDLE h_token;
    T_bool bRet = FALSE;
    if (OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&h_token))
    {
        TOKEN_PRIVILEGES tkp;
        if (LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid))
        {
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            bRet = AdjustTokenPrivileges(h_token,FALSE,&tkp,sizeof(TOKEN_PRIVILEGES),NULL,NULL);
        }
        CloseHandle(h_token);
    }
    return bRet;
}

T_bool blpp_System_GetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType)
{
    HKEY hk;
    LONG retin;
    DWORD ret;
    if (NULL==out_data || NULL==out_size)
    {
        return FALSE;
    }
    retin = RegOpenKeyExA(hKey,lpSubKey,0,KEY_READ,&hk);
    if (ERROR_SUCCESS == retin)
    {
        retin = RegQueryValueExA(hk,lpValueName,NULL,lpType,NULL,&ret);
        if (ERROR_SUCCESS == retin)
        {
            if (ret <= *out_size)
            {
                *out_size = ret;
                retin = RegQueryValueExA(hk,lpValueName,NULL,lpType,out_data,&ret);
                if (ERROR_SUCCESS == retin)
                {
                    RegCloseKey(hk);
                    return TRUE;
                }
            }
            else
            {
                *out_size = ret;
            }
        }
        RegCloseKey(hk);
    }
    return FALSE;
}

T_bool blpp_System_GetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PT_byte out_data,PT_Dword out_size,LPDWORD lpType)
{
    HKEY hk;
    LONG retin;
    DWORD ret;
    if (NULL==out_data || NULL==out_size)
    {
        return FALSE;
    }
    retin = RegOpenKeyExW(hKey,lpSubKey,0,KEY_READ,&hk);
    if (ERROR_SUCCESS == retin)
    {
        retin = RegQueryValueExW(hk,lpValueName,NULL,lpType,NULL,&ret);
        if (ERROR_SUCCESS == retin)
        {
            if (ret <= *out_size)
            {
                *out_size = ret;
                retin = RegQueryValueExW(hk,lpValueName,NULL,lpType,out_data,&ret);
                if (ERROR_SUCCESS == retin)
                {
                    RegCloseKey(hk);
                    return TRUE;
                }
            }
            else
            {
                *out_size = ret;
            }
        }
        RegCloseKey(hk);
    }
    return FALSE;
}

T_bool blpp_System_SetRegDataA(HKEY hKey,PCT_str lpSubKey,PCT_str lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type)
{
    HKEY hk;
    LONG ret;
    if (NULL == in_data)
    {
        return FALSE;
    }
    ret = RegOpenKeyExA(hKey,lpSubKey,0,KEY_WRITE,&hk);
    if (ERROR_SUCCESS == ret)
    {
        ret = RegSetValueExA(hk,lpValueName,0,Type,in_data,in_size);
        if (ERROR_SUCCESS == ret)
        {
            RegCloseKey(hk);
            return TRUE;
        }
        RegCloseKey(hk);
    }
    return FALSE;
}

T_bool blpp_System_SetRegDataW(HKEY hKey,PCT_wstr lpSubKey,PCT_wstr lpValueName,PCT_byte in_data,T_Dword in_size,DWORD Type)
{
    HKEY hk;
    LONG ret;
    if (NULL == in_data)
    {
        return FALSE;
    }
    ret = RegOpenKeyExW(hKey,lpSubKey,0,KEY_WRITE,&hk);
    if (ERROR_SUCCESS == ret)
    {
        ret = RegSetValueExW(hk,lpValueName,0,Type,in_data,in_size);
        if (ERROR_SUCCESS == ret)
        {
            RegCloseKey(hk);
            return TRUE;
        }
        RegCloseKey(hk);
    }
    return FALSE;
}


//
// Object hack.
//

T_void blpp_Object_RefreshPrefix()
{
    ObjUpdateDosDevicePrefixes();
    ObjUpdateMupDevicePrefixes();
}

T_bool blpp_Object_GetFormattedFileName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize)
{
    if (NULL==strIn || NULL==strOut)
    {
        return FALSE;
    }
    wstring wstr = strIn;
    bool bRet = ObjGetFileName(wstr);
    size_t len = wstr.length();
    if (len < outSize/sizeof(T_wchar))
    {
        memcpy(strOut,wstr.data(),len*sizeof(T_wchar));
        strOut[len] = 0;
    }
    else
    {
        return FALSE;
    }
    return bRet;
}

T_bool blpp_Object_GetFormattedKeyName(PCT_wstr strIn,PT_wstr strOut,T_Dword outSize)
{
    if (NULL==strIn || NULL==strOut)
    {
        return FALSE;
    }
    wstring wstr = strIn;
    bool bRet = ObjFormatNativeKeyName(wstr);
    size_t len = wstr.length();
    if (len < outSize/sizeof(T_wchar))
    {
        memcpy(strOut,wstr.data(),len*sizeof(T_wchar));
        strOut[len] = 0;
    }
    else
    {
        return FALSE;
    }
    return bRet;
}

T_bool blpp_Object_QueryHandleInfo
(
    HANDLE Handle,
	T_bool bCanWait,
    OBJ_OBJECT_TYPE *ObjType,
    PT_Dword refCount,
    PT_wstr nameOut,
    T_Dword outSize,
    PT_Dword PID,
    PT_Dword TID
)
{
    OBJECT_BASIC_INFORMATION objInfo;
    CLIENT_ID cid;
    wstring typeName;
    wstring bestName;
    NTSTATUS st;
    cid.UniqueProcess = NULL;
    cid.UniqueThread = NULL;
    // First check special.
    if (NULL == Handle)
    {
        return FALSE;
    }
    else if (NtCurrentProcess() == Handle)
    {
        if (ObjType)
        {
            *ObjType = OBJ_TYPE_Process;
        }
        if (refCount)
        {
            *refCount = T_MAX_BIT32U;
        }
        if (PID)
        {
            *PID = GetCurrentProcessId();
        }
    }
    else if (NtCurrentThread() == Handle)
    {
        if (ObjType)
        {
            *ObjType = OBJ_TYPE_Thread;
        }
        if (refCount)
        {
            *refCount = T_MAX_BIT32U;
        }
        if (PID)
        {
            *PID = GetCurrentProcessId();
        }
        if (TID)
        {
            *TID = GetCurrentThreadId();
        }
    }
    st = ObjGetHandleInformation(Handle,bCanWait,&objInfo,ObjType,typeName,bestName,&cid);
    if (!NT_SUCCESS(st))
    {
        return FALSE;
    }
    if (refCount)
    {
        *refCount = objInfo.HandleCount;
    }
    size_t len = bestName.length();
    if (nameOut && (len<(outSize/sizeof(T_wchar))))
    {
        memcpy(nameOut,bestName.data(),len*sizeof(T_wchar));
        nameOut[len] = 0;
    }
    if (PID)
    {
        *PID = (T_Dword)cid.UniqueProcess;
    }
    if (TID)
    {
        *TID = (T_Dword)cid.UniqueThread;
    }
    return TRUE;
}


//
// sqlite3
//

PT_void blpp_sqlite_OpenDB(PCT_str szPath,T_bool bCreate,T_bool bWrite,PCT_str *errString)
{
    if (NULL == szPath)
    {
        return NULL;
    }
    sqlite3 *db = NULL;
    int r = sqlite3_open_v2(szPath,&db,(bCreate?SQLITE_OPEN_CREATE:0)|(bWrite?SQLITE_OPEN_READWRITE:SQLITE_OPEN_READONLY),NULL);
    if (r)
    {
        if (errString)
        {
            *errString = sqlite3_errmsg(db);
        }
        if (db)
        {
            sqlite3_close_v2(db);
        }
        return NULL;
    }
    return db;
}

T_void blpp_sqlite_CloseDB(PT_void db)
{
    if (db)
    {
        sqlite3_close_v2((sqlite3 *)db);
    }
}

T_bool blpp_sqlite_Exec(PT_void db,PCT_str sql,__pfn_blpp_sqlite_callback callback,PT_void lparam,PT_str errStringBuffer,T_Dword bufferLength)
{
    if (NULL==db || NULL==sql)
    {
        return FALSE;
    }
    char *errStr = NULL;
    int re = sqlite3_exec((sqlite3 *)db,sql,callback,lparam,&errStr);
    if (errStr)
    {
        if (errStringBuffer)
        {
            size_t len = strlen(errStr);
            if (len < bufferLength)
            {
                memcpy(errStringBuffer,errStr,len+1);
            }
            else
            {
                memcpy(errStringBuffer,errStr,bufferLength-1);
                errStringBuffer[bufferLength-1] = 0;
            }
        }
        sqlite3_free(errStr);
    }
    return re?FALSE:TRUE;
}


//
// Thread Local Slot
//

T_bool blpp_Tls_FlagOn(T_address Flag)
{
    return IsThreadFlagOn(my_tls,Flag);
}

T_bool blpp_Tls_SetFlag(T_address Flag)
{
    return SetThreadFlag(my_tls,Flag);
}

T_bool blpp_Tls_ClearFlag(T_address Flag)
{
    return ClearThreadFlag(my_tls,Flag);
}

T_bool blpp_Tls_CheckAndSetFlag(T_address Flag) // If flag is on,return FALSE.
{
    return CheckAndSetThreadFlag(my_tls,Flag);
}
