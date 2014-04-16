//////////////////////////////////////////////////////////////////////////
// File name symbol link to pass SSDT hook

#include "../basic_fun.h"

#define BYPASS_DEF_A "sysA"
#define BYPASS_LNK_A "\\\\.\\sysA"
#define BYPASS_DEF_W L"sysW"
#define BYPASS_LNK_W L"\\\\.\\sysW"

class filePathLinkA
{
private:
    string m_TmpPathDef;
    string m_TmpPathLink;
    string m_TmpFilePath;
    char m_TmpNumber[20];
public:
    filePathLinkA(PCT_str lpFileName)
        :m_TmpPathDef(BYPASS_DEF_A),m_TmpPathLink(BYPASS_LNK_A),m_TmpFilePath("\\??\\")
    {
        static T_Dword tick = 0;
        _ltoa_s(GetTickCount()*GetCurrentThreadId()+(++tick),m_TmpNumber,20,16);
        m_TmpFilePath.append(lpFileName);
        m_TmpPathDef.append(m_TmpNumber);
        m_TmpPathLink.append(m_TmpNumber);
    }
    ~filePathLinkA()
    {
        DWORD LastError = GetLastError();
        DefineDosDeviceA(DDD_REMOVE_DEFINITION,m_TmpPathDef.c_str(),m_TmpFilePath.c_str());
        SetLastError(LastError);
    }
    const string &getLink()
    {
        DefineDosDeviceA(DDD_RAW_TARGET_PATH,m_TmpPathDef.c_str(),m_TmpFilePath.c_str());
        return m_TmpPathLink;
    }
};

class filePathLinkW
{
private:
    wstring m_TmpPathDef;
    wstring m_TmpPathLink;
    wstring m_TmpFilePath;
    wchar_t m_TmpNumber[20];
public:
    filePathLinkW(PCT_wstr lpFileName)
        :m_TmpPathDef(BYPASS_DEF_W),m_TmpPathLink(BYPASS_LNK_W),m_TmpFilePath(L"\\??\\")
    {
        static T_Dword tick = 0;
        _ltow_s(GetTickCount()*GetCurrentThreadId()+(++tick),m_TmpNumber,20,16);
        m_TmpFilePath.append(lpFileName);
        m_TmpPathDef.append(m_TmpNumber);
        m_TmpPathLink.append(m_TmpNumber);
    }
    ~filePathLinkW()
    {
        DWORD LastError = GetLastError();
        DefineDosDeviceW(DDD_REMOVE_DEFINITION,m_TmpPathDef.c_str(),m_TmpFilePath.c_str());
        SetLastError(LastError);
    }
    const wstring &getLink()
    {
        DefineDosDeviceW(DDD_RAW_TARGET_PATH,m_TmpPathDef.c_str(),m_TmpFilePath.c_str());
        return m_TmpPathLink;
    }
};

HANDLE blpp_fs_CreateFileBypassA(PCT_str lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes)
{
    filePathLinkA link(lpPathName);
    return CreateFileA
        (link.getLink().c_str(),
        dwDesiredAccess,
        dwShareMode,
        NULL,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        NULL);
}

HANDLE blpp_fs_CreateFileBypassW(PCT_wstr lpPathName,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes)
{
    filePathLinkW link(lpPathName);
    return CreateFileW
        (link.getLink().c_str(),
        dwDesiredAccess,
        dwShareMode,
        NULL,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        NULL);
}

T_bool blpp_fs_CreateDirectoryBypassA(PCT_str lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    filePathLinkA link(lpPathName);
    return CreateDirectoryA(link.getLink().c_str(),lpSecurityAttributes);
}

T_bool blpp_fs_CreateDirectoryBypassW(PCT_wstr lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    filePathLinkW link(lpPathName);
    return CreateDirectoryW(link.getLink().c_str(),lpSecurityAttributes);
}

T_bool blpp_fs_RemoveDirectoryBypassA(PCT_str lpPathName)
{
    filePathLinkA link(lpPathName);
    return RemoveDirectoryA(link.getLink().c_str());
}

T_bool blpp_fs_RemoveDirectoryBypassW(PCT_wstr lpPathName)
{
    filePathLinkW link(lpPathName);
    return RemoveDirectoryW(link.getLink().c_str());
}

T_bool blpp_fs_DeleteFileBypassA(PCT_str lpFileName)
{
    HANDLE hf;
    hf = blpp_fs_CreateFileBypassA(lpFileName,DELETE,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING,FILE_FLAG_DELETE_ON_CLOSE);
    if (INVALID_HANDLE_VALUE == hf)
    {
        CloseHandle(hf);
        return TRUE;
    }
    return FALSE;
}

T_bool blpp_fs_DeleteFileBypassW(PCT_wstr lpFileName)
{
    HANDLE hf;
    hf = blpp_fs_CreateFileBypassW(lpFileName,DELETE,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING,FILE_FLAG_DELETE_ON_CLOSE);
    if (INVALID_HANDLE_VALUE == hf)
    {
        CloseHandle(hf);
        return TRUE;
    }
    return FALSE;
}

T_bool blpp_fs_MoveFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName)
{
    filePathLinkA link1(lpExistingFileName),link2(lpNewFileName);
    return MoveFileA(link1.getLink().c_str(),link2.getLink().c_str());
}

T_bool blpp_fs_MoveFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName)
{
    filePathLinkW link1(lpExistingFileName),link2(lpNewFileName);
    return MoveFileW(link1.getLink().c_str(),link2.getLink().c_str());
}

T_bool blpp_fs_CopyFileBypassA(PT_str lpExistingFileName,PT_str lpNewFileName,T_bool bFailIfExists)
{
    filePathLinkA link1(lpExistingFileName),link2(lpNewFileName);
    return CopyFileA(link1.getLink().c_str(),link2.getLink().c_str(),bFailIfExists);
}

T_bool blpp_fs_CopyFileBypassW(PT_wstr lpExistingFileName,PT_wstr lpNewFileName,T_bool bFailIfExists)
{
    filePathLinkW link1(lpExistingFileName),link2(lpNewFileName);
    return CopyFileW(link1.getLink().c_str(),link2.getLink().c_str(),bFailIfExists);
}

T_bool blpp_fs_GetFileAttributesBypassA(PT_str lpPathName,PDWORD pAttr)
{
    filePathLinkA link(lpPathName);
    DWORD Attr;
    Attr = GetFileAttributesA(link.getLink().c_str());
    if (pAttr)
    {
        *pAttr = Attr;
    }
    return (INVALID_FILE_ATTRIBUTES != GetLastError());
}

T_bool blpp_fs_GetFileAttributesBypassW(PT_wstr lpPathName,PDWORD pAttr)
{
    filePathLinkW link(lpPathName);
    DWORD Attr;
    Attr = GetFileAttributesW(link.getLink().c_str());
    if (pAttr)
    {
        *pAttr = Attr;
    }
    return (INVALID_FILE_ATTRIBUTES != GetLastError());
}

T_bool blpp_fs_SetFileAttributesBypassA(PT_str lpPathName,DWORD dwAttr)
{
    filePathLinkA link(lpPathName);
    return SetFileAttributesA(link.getLink().c_str(),dwAttr);
}

T_bool blpp_fs_SetFileAttributesBypassW(PT_wstr lpPathName,DWORD dwAttr)
{
    filePathLinkW link(lpPathName);
    return SetFileAttributesW(link.getLink().c_str(),dwAttr);
}
