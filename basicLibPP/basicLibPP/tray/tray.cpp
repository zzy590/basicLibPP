
#include "../basic_fun.h"
#include <Shellapi.h>
#include <strsafe.h>


//////////////////////////////////////////////////////////////////////////


typedef struct _BLPP_TRAY_CONTEXT
{
    HANDLE hEvent;
    BOOL bExit;
    HANDLE hThread;
    HICON hIcon;
    HWND hWnd;
    UINT Message;
    TCHAR Tip[64];
    UINT Id;
} BLPP_TRAY_CONTEXT, *PBLPP_TRAY_CONTEXT;


//////////////////////////////////////////////////////////////////////////


DWORD WINAPI TrayThreadProc(LPVOID lpParameter)
{
    // Put into internal thread set.
    LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
    blpp_internalThreadSet.insert(GetCurrentThreadId());
    LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
    // Now monitor for tray.
    PBLPP_TRAY_CONTEXT pCtx = (PBLPP_TRAY_CONTEXT)lpParameter;
    NOTIFYICONDATA nid;
    ZeroMemory(&nid,sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = pCtx->hWnd;
    StringCbCopy(nid.szTip,64,pCtx->Tip);
    nid.uCallbackMessage = pCtx->Message;
    nid.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE;
    nid.uID = pCtx->Id;
    while (true)
    {
        if (WAIT_OBJECT_0 == WaitForSingleObject(pCtx->hEvent,2000)) // Flush per 2s.
        {
            if (pCtx->bExit)
            {
                Shell_NotifyIcon(NIM_DELETE,&nid);
                break;
            }
            nid.hIcon = pCtx->hIcon;
        }
        if (!Shell_NotifyIcon(NIM_MODIFY,&nid))
        {
            Shell_NotifyIcon(NIM_ADD,&nid);
        }
    }
    // Remove from set.
    LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
    blpp_internalThreadSet.erase(GetCurrentThreadId());
    LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
    return 0;
}

T_bool blpp_Tray_ChangeIcon(PBLPP_TRAY_CONTEXT pCtx,HICON hIcon)
{
    if (NULL == pCtx)
    {
        return FALSE;
    }
    pCtx->hIcon = hIcon;
    SetEvent(pCtx->hEvent);
    return TRUE;
}

T_bool blpp_Tray_BalloonMessage(PBLPP_TRAY_CONTEXT pCtx,PCT_str szMsg,PCT_str szTitle)
{
    if (NULL==pCtx || NULL==szMsg || NULL==szTitle)
    {
        return FALSE;
    }
    NOTIFYICONDATA nid;
    ZeroMemory(&nid,sizeof(nid));
    nid.cbSize = sizeof(nid);
    StringCbCopy(nid.szInfo,256,szMsg);
    StringCbCopy(nid.szInfoTitle,64,szTitle);
    nid.uTimeout = 5;
    nid.dwInfoFlags = NIIF_USER;
    nid.hIcon = pCtx->hIcon;
    nid.hWnd = pCtx->hWnd;
    nid.uID = pCtx->Id;
    StringCbCopy(nid.szTip,64,pCtx->Tip);
    nid.uCallbackMessage = pCtx->Message;
    nid.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE|NIF_INFO;
    if (!Shell_NotifyIcon(NIM_MODIFY,&nid))
    {
        Shell_NotifyIcon(NIM_ADD,&nid);
    }
    return TRUE;
}

PBLPP_TRAY_CONTEXT blpp_Tray_CreateNewTray(HICON hIcon,HWND hWnd,UINT Message,PCT_str szTip,UINT Id)
{
    if (NULL==hIcon || NULL==hWnd || NULL==szTip)
    {
        return NULL;
    }
    PBLPP_TRAY_CONTEXT pCtx = (PBLPP_TRAY_CONTEXT)blpp_mem_alloc(sizeof(BLPP_TRAY_CONTEXT));
    if (NULL == pCtx)
    {
        return NULL;
    }
    pCtx->hEvent = CreateEvent(NULL,FALSE,TRUE,NULL);
    if (NULL == pCtx->hEvent)
    {
        blpp_mem_free(pCtx);
        return NULL;
    }
    pCtx->bExit = FALSE;
    pCtx->hIcon = hIcon;
    pCtx->hWnd = hWnd;
    pCtx->Message = Message;
    StringCbCopy(pCtx->Tip,64,szTip);
    pCtx->Id = Id;
    pCtx->hThread = CreateThread(0,0,TrayThreadProc,pCtx,0,0);
    if (NULL == pCtx->hThread)
    {
        CloseHandle(pCtx->hEvent);
        blpp_mem_free(pCtx);
        return NULL;
    }
    return pCtx;
}

T_bool blpp_Tray_DestoryTray(PBLPP_TRAY_CONTEXT pCtx)
{
    if (NULL == pCtx)
    {
        return FALSE;
    }
    pCtx->bExit = TRUE;
    SetEvent(pCtx->hEvent);
    WaitForSingleObject(pCtx->hThread,INFINITE);
    CloseHandle(pCtx->hThread);
    CloseHandle(pCtx->hEvent);
    blpp_mem_free(pCtx);
    return TRUE;
}
