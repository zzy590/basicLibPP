
#include "basic_fun.h"

static bool bInitErr = false;

BOOL WINAPI DllMain(HINSTANCE hinst,DWORD dwReason,LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!blpp_init())
        {
            bInitErr = true;
            return FALSE;
        }
        blpp_Hook_AddThread(GetCurrentThreadId());
        break;
    case DLL_PROCESS_DETACH:
        if (!bInitErr)
        {
            blpp_uninit();
        }
        break;
    case DLL_THREAD_ATTACH:
        blpp_Hook_AddThread(GetCurrentThreadId());
        break;
    case DLL_THREAD_DETACH:
        blpp_Hook_RemoveThread(GetCurrentThreadId());
        break;
    default:
        break;
    }
    return TRUE;
}
