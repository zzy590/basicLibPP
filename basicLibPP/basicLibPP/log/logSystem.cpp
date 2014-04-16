
/************************************************************************/
/* Log system library                                                   */
/************************************************************************/

#include "../basic_fun.h"
#include <string>
#include <strsafe.h>

using namespace std;

/************************************************************************/

static BLPP_QUEUED_LOCK logLock = BLPP_QUEUED_LOCK_INIT;
static string logDir;
static HANDLE hFile = INVALID_HANDLE_VALUE;

/************************************************************************/

T_bool blpp_Log_SetLogDirectory(PCT_str szPath)
{
    if (NULL == szPath)
    {
        return false;
    }
    AutoQueuedLock aql(logLock,true);
    logDir = szPath;
    if (logDir.length() && logDir[logDir.length()-1]!='\\')
    {
        logDir.append("\\");
    }
    return true;
}

#define TEMP_STRING_LENGTH (200)
#define LOG_BUFFER_SIZE (16*1024)

T_void blpp_Log_DebugLog(PCT_str Target,...)
{
    AutoQueuedLock aql(logLock,true);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        T_char PathStr[Config_MAX_PATH];
        StringCbPrintfA(PathStr,Config_MAX_PATH,"%sPID_%d_%X.log",logDir.c_str(),GetCurrentProcessId(),GetTickCount());
        hFile = CreateFileA(PathStr,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if (INVALID_HANDLE_VALUE == hFile)
        {
            return;
        }
    }
    // Now for log.
    SYSTEMTIME Time;
    T_char TmpStr[TEMP_STRING_LENGTH];
    GetLocalTime(&Time);
    StringCbPrintfA(TmpStr,TEMP_STRING_LENGTH,"/************************************************************************/\r\nDate: %d Y %d M %d D  Time: %d:%d:%d\r\n\r\n",Time.wYear,Time.wMonth,Time.wDay,Time.wHour,Time.wMinute,Time.wSecond);
    DWORD re;
    WriteFile(hFile,TmpStr,(DWORD)strlen(TmpStr),&re,0);
    // Form the data.
    va_list args;
    PT_str pData;
    pData = (PT_str)blpp_mem_alloc(LOG_BUFFER_SIZE);
    if (pData)
    {
        va_start(args,Target);
        StringCbVPrintfA(pData,LOG_BUFFER_SIZE,Target,args);
        va_end(args);
        WriteFile(hFile,pData,(DWORD)strlen(pData),&re,0);
        blpp_mem_free(pData);
    }
    else
    {
        StringCbCopyA(TmpStr,TEMP_STRING_LENGTH,"<INSUFFICIENT_RESOURCES>");
        WriteFile(hFile,TmpStr,(DWORD)strlen(TmpStr),&re,0);
    }
    // Write end.
    StringCbCopyA(TmpStr,TEMP_STRING_LENGTH,"\r\n\r\n\r\n");
    WriteFile(hFile,TmpStr,(DWORD)strlen(TmpStr),&re,0);
}
