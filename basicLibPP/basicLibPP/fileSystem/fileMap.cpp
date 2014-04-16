//////////////////////////////////////////////////////////////////////////
// File map to memory to pass SSDT hook

#include "../basic_fun.h"

static T_status LoadFileAsMemory(HANDLE hFile,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite)
{
    HANDLE hMapping;
    LPVOID ImageBase;
    LARGE_INTEGER Size;
    if (INVALID_HANDLE_VALUE == hFile)
    {
        DWORD LastErr = GetLastError();
        if (ERROR_FILE_NOT_FOUND == LastErr ||
            ERROR_PATH_NOT_FOUND == LastErr)
        {
            return T_STATUS_NOT_FOUND;
        }
        return T_STATUS_ACCESS_DENIED;
    }
    if (!GetFileSizeEx(hFile,&Size))
    {
        CloseHandle(hFile);
        return T_STATUS_ACCESS_DENIED;
    }
    pMapFile->FileSize = Size;
    hMapping = CreateFileMapping
        (hFile,NULL,
        bToWrite?(PAGE_READWRITE):(PAGE_READONLY),
        0,0,NULL);
    if(NULL == hMapping)
    {
        CloseHandle(hFile);
        return T_STATUS_ACCESS_DENIED;
    }
    ImageBase = MapViewOfFile
        (hMapping,
        bToWrite?(FILE_MAP_READ|FILE_MAP_WRITE):(FILE_MAP_READ),
        0,0,0);
    if(NULL == ImageBase)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return T_STATUS_ACCESS_DENIED;
    }
    pMapFile->hFile = hFile;
    pMapFile->hMapping = hMapping;
    pMapFile->ImageBase = ImageBase;
    return T_STATUS_SUCCESS;
}

T_status blpp_fs_LoadFileAsMemoryA(PCT_str lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass)
{
    HANDLE hFile;
    if (bUseBypass)
    {
        hFile = blpp_fs_CreateFileBypassA
            (lpFilename,
            bToWrite?(GENERIC_READ|GENERIC_WRITE):(GENERIC_READ),
            bToWrite?(FILE_SHARE_READ|FILE_SHARE_WRITE):(FILE_SHARE_READ),
            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
    }
    else
    {
        hFile = CreateFileA
            (lpFilename,
            bToWrite?(GENERIC_READ|GENERIC_WRITE):(GENERIC_READ),
            bToWrite?(FILE_SHARE_READ|FILE_SHARE_WRITE):(FILE_SHARE_READ),
            NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    }
    return LoadFileAsMemory(hFile,pMapFile,bToWrite);
}

T_status blpp_fs_LoadFileAsMemoryW(PCT_wstr lpFilename,PBLPP_MAP_FILE_STRUCT pMapFile,T_bool bToWrite,T_bool bUseBypass)
{
    HANDLE hFile;
    if (bUseBypass)
    {
        hFile = blpp_fs_CreateFileBypassW
            (lpFilename,
            bToWrite?(GENERIC_READ|GENERIC_WRITE):(GENERIC_READ),
            bToWrite?(FILE_SHARE_READ|FILE_SHARE_WRITE):(FILE_SHARE_READ),
            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
    }
    else
    {
        hFile = CreateFileW
            (lpFilename,
            bToWrite?(GENERIC_READ|GENERIC_WRITE):(GENERIC_READ),
            bToWrite?(FILE_SHARE_READ|FILE_SHARE_WRITE):(FILE_SHARE_READ),
            NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    }
    return LoadFileAsMemory(hFile,pMapFile,bToWrite);
}

T_void blpp_fs_UnLoadFileMemory(PBLPP_MAP_FILE_STRUCT pMapFile)
{
    if(pMapFile->ImageBase)
    {
        UnmapViewOfFile(pMapFile->ImageBase);
        pMapFile->ImageBase = NULL;
    }
    if(pMapFile->hMapping)
    {
        CloseHandle(pMapFile->hMapping);
        pMapFile->hMapping = NULL;
    }
    if(pMapFile->hFile)
    {
        CloseHandle(pMapFile->hFile);
        pMapFile->hFile = NULL;
    }
    pMapFile->FileSize.QuadPart = 0;
}
