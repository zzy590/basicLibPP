//////////////////////////////////////////////////////////////////////////
// File name symbol link to pass SSDT hook

#include "../basic_fun.h"

#include <strsafe.h>

#define FS_BYPASS_DEFINE_PREFIX_A "blpp_"
#define FS_BYPASS_DEFINE_PREFIX_W L"blpp_"

class filePathLinkA
{
private:
	string m_ntType;
	string m_pathDefine;
	string m_pathLink;
	bool m_transformed;
public:
	filePathLinkA(const string& path) :m_ntType("\\??\\")
	{
		if (path.length() > 4 && path.substr(0, 4) == "\\??\\")
		{
			m_ntType.append(path.substr(4));
		}
		else
		{
			m_ntType.append(path);
		}
		static DWORD tick = 0;
		char tmpBuffer[100];
		StringCbPrintfA(tmpBuffer, 100, "%x%x%x%x", GetCurrentThreadId(), GetTickCount(), rand(), ++tick);
		m_pathDefine = string(FS_BYPASS_DEFINE_PREFIX_A) + tmpBuffer;
		if (DefineDosDeviceA(DDD_RAW_TARGET_PATH, m_pathDefine.c_str(), m_ntType.c_str()))
		{
			m_pathLink = string("\\\\.\\") + FS_BYPASS_DEFINE_PREFIX_A + tmpBuffer;
			m_transformed = true;
		}
		else
		{
			m_pathLink = path;
			m_transformed = false;
		}
	}
	~filePathLinkA()
	{
		if (m_transformed)
		{
			DWORD err = GetLastError();
			DefineDosDeviceA(DDD_REMOVE_DEFINITION, m_pathDefine.c_str(), m_ntType.c_str());
			SetLastError(err);
		}
	}

	const string& getLink() const
	{
		return m_pathLink;
	}
};

class filePathLinkW
{
private:
	wstring m_ntType;
	wstring m_pathDefine;
	wstring m_pathLink;
	bool m_transformed;
public:
	filePathLinkW(const wstring& path) :m_ntType(L"\\??\\")
	{
		if (path.length() > 4 && path.substr(0, 4) == L"\\??\\")
		{
			m_ntType.append(path.substr(4));
		}
		else
		{
			m_ntType.append(path);
		}
		static DWORD tick = 0;
		wchar_t tmpBuffer[100];
		StringCbPrintfW(tmpBuffer, 100, L"%x%x%x%x", GetCurrentThreadId(), GetTickCount(), rand(), ++tick);
		m_pathDefine = wstring(FS_BYPASS_DEFINE_PREFIX_W) + tmpBuffer;
		if (DefineDosDeviceW(DDD_RAW_TARGET_PATH, m_pathDefine.c_str(), m_ntType.c_str()))
		{
			m_pathLink = wstring(L"\\\\.\\") + FS_BYPASS_DEFINE_PREFIX_W + tmpBuffer;
			m_transformed = true;
		}
		else
		{
			m_pathLink = path;
			m_transformed = false;
		}
	}
	~filePathLinkW()
	{
		if (m_transformed)
		{
			DWORD err = GetLastError();
			DefineDosDeviceW(DDD_REMOVE_DEFINITION, m_pathDefine.c_str(), m_ntType.c_str());
			SetLastError(err);
		}
	}

	const wstring& getLink() const
	{
		return m_pathLink;
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
	if (hf != INVALID_HANDLE_VALUE)
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
	if (hf != INVALID_HANDLE_VALUE)
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
	return INVALID_FILE_ATTRIBUTES != Attr;
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
	return INVALID_FILE_ATTRIBUTES != Attr;
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
