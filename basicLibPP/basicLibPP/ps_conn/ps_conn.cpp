
#include "../basic_fun.h"
#include <string>

using namespace std;

//
// Pipe
//

#define PSCONN_TIMEOUT (1000) // 1s

T_bool blpp_Pipe_CreateLinker(PHANDLE hRead,PHANDLE hWrite)
{
    return CreatePipe(hRead,hWrite,NULL,0);
}

HANDLE blpp_Pipe_CreateNamedLinker(PCT_str LinkerName,T_bool WithLowestSecurity)
{
    HANDLE hPipe;
    string LinkerPipeName = "\\\\.\\Pipe\\";
    LinkerPipeName.append(LinkerName);
    SECURITY_DESCRIPTOR secutityDese;
    SECURITY_ATTRIBUTES securityAttr;
    // set SECURITY_DESCRIPTOR
    InitializeSecurityDescriptor(&secutityDese,SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&secutityDese,TRUE,NULL,FALSE);
    // set SECURITY_ATTRIBUTES
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = FALSE;
    securityAttr.lpSecurityDescriptor = &secutityDese;
    hPipe = CreateNamedPipeA(LinkerPipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        0,
        0,
        PSCONN_TIMEOUT,
        (WithLowestSecurity)?(&securityAttr):(NULL));
    if (INVALID_HANDLE_VALUE == hPipe)
    {
        hPipe = NULL;
    }
    return hPipe;
}

T_bool blpp_Pipe_Accept(HANDLE hConn)
{
    return ConnectNamedPipe(hConn,NULL);
}

T_bool blpp_Pipe_Disconnect(HANDLE hConn)
{
    return DisconnectNamedPipe(hConn);
}

T_bool blpp_Pipe_WaitServerOk(PCT_str LinkerName,T_Dword nTimeOut)
{
    string LinkerPipeName = "\\\\.\\Pipe\\";
    LinkerPipeName.append(LinkerName);
    return WaitNamedPipeA(LinkerPipeName.c_str(),nTimeOut);
}

HANDLE blpp_Pipe_Connect(PCT_str LinkerName,T_bool WithLowestSecurity)
{
    HANDLE hPipe;
    string LinkerPipeName = "\\\\.\\Pipe\\";
    LinkerPipeName.append(LinkerName);
    SECURITY_DESCRIPTOR secutityDese;
    SECURITY_ATTRIBUTES securityAttr;
    // set SECURITY_DESCRIPTOR
    InitializeSecurityDescriptor(&secutityDese,SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&secutityDese,TRUE,NULL,FALSE);
    // set SECURITY_ATTRIBUTES
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = FALSE;
    securityAttr.lpSecurityDescriptor = &secutityDese;
    hPipe = CreateFileA(LinkerPipeName.c_str(),
        GENERIC_READ|GENERIC_WRITE,
        0,
        (WithLowestSecurity)?(&securityAttr):(NULL),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == hPipe)
    {
        hPipe = NULL;
    }
    return hPipe;
}

T_Dword blpp_Pipe_Send(HANDLE hConn,PCT_void Data,T_Dword Length)
{
    DWORD re;
    if (!WriteFile(hConn,Data,Length,&re,0))
    {
        re = 0;
    }
    return re;
}

T_Dword blpp_Pipe_Recv(HANDLE hConn,PT_void Data,T_Dword Length)
{
    DWORD re;
    if (!ReadFile(hConn,Data,Length,&re,0))
    {
        if (ERROR_MORE_DATA == GetLastError())
        {
            re = T_MAX_BIT32U;
        }
        else
        {
            re = 0;
        }
    }
    return re;
}

//
// Payload.
//

#define PAYLOAD_PACK_SIGNATURE 'pplb'

#include <PshPack1.h>

typedef struct _PAYLOAD_PACK
{
    T_Dword Signature;
    T_byte SignMD5[16];
    T_Dword DataLength;
} PAYLOAD_PACK, *PPAYLOAD_PACK;

#include <PopPack.h>

PT_void blpp_Payload_FindNativePack(PCT_str Identity,PT_Dword DataLength)
{
    PT_byte pbLast = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    T_byte MD5[16];
    blpp_Hash_MD5(Identity,strlen(Identity),MD5);
    ZeroMemory(&mbi,sizeof(mbi));
    //
    // Find the next memory region that contains a mapped PE image.
    //
    for (;; pbLast = (PT_byte)mbi.BaseAddress + mbi.RegionSize)
    {
        if (0 == VirtualQuery(pbLast,&mbi,sizeof(mbi)))
        {
            break;
        }
		if ((mbi.RegionSize & 0xfff) == 0xfff)
		{
			break;
		}
        if (((PBYTE)mbi.BaseAddress + mbi.RegionSize) < pbLast)
        {
            break;
        }
        //
        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_COMMIT) ||
            ((mbi.Protect & 0xff) == PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD))
        {
            continue;
        }
        if (mbi.RegionSize < sizeof(PAYLOAD_PACK))
        {
            continue;
        }
        __try
        {
            PPAYLOAD_PACK pPayload;
            pPayload = (PPAYLOAD_PACK)pbLast;
            if (PAYLOAD_PACK_SIGNATURE != pPayload->Signature)
            {
                continue;
            }
            if (0 != memcmp(pPayload->SignMD5,MD5,16))
            {
                continue;
            }
            if (mbi.RegionSize < sizeof(PAYLOAD_PACK)+pPayload->DataLength)
            {
                continue;
            }
            if (DataLength)
            {
                *DataLength = pPayload->DataLength;
            }
            return (PT_void)(pPayload + 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }
    return NULL;
}

PT_void blpp_Payload_AddNativePack(PCT_str Identity,PCT_void Data,T_Dword DataLength)
{
    PPAYLOAD_PACK pPayload;
    pPayload = (PPAYLOAD_PACK)VirtualAlloc(NULL,sizeof(PAYLOAD_PACK)+DataLength,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (NULL == pPayload)
    {
        return NULL;
    }
    memcpy(pPayload+1,Data,DataLength);
    // Set head and sign at last.
    blpp_Hash_MD5(Identity,strlen(Identity),pPayload->SignMD5);
    pPayload->DataLength = DataLength;
    pPayload->Signature = PAYLOAD_PACK_SIGNATURE;
    return pPayload+1;
}

T_bool blpp_Payload_FreeNativePack(PT_void pData)
{
    return VirtualFree(((PT_byte)pData)-sizeof(PAYLOAD_PACK),0,MEM_RELEASE);
}

PT_void blpp_Payload_FindRemotePack(HANDLE hProcess,PCT_str Identity,PT_Dword DataLength)
{
    PT_byte pbLast = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    T_byte MD5[16];
    blpp_Hash_MD5(Identity,strlen(Identity),MD5);
    ZeroMemory(&mbi,sizeof(mbi));
    //
    // Find the next memory region that contains a mapped PE image.
    //
    for (;; pbLast = (PT_byte)mbi.BaseAddress + mbi.RegionSize)
    {
        if (0 == VirtualQueryEx(hProcess,pbLast,&mbi,sizeof(mbi)))
        {
            break;
        }
		if ((mbi.RegionSize & 0xfff) == 0xfff)
		{
			break;
		}
        if (((PBYTE)mbi.BaseAddress + mbi.RegionSize) < pbLast)
        {
            break;
        }
        //
        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_COMMIT) ||
            ((mbi.Protect & 0xff) == PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD))
        {
            continue;
        }
        if (mbi.RegionSize < sizeof(PAYLOAD_PACK))
        {
            continue;
        }
        __try
        {
            PAYLOAD_PACK Payload;
            SIZE_T re;
            if ((!ReadProcessMemory(hProcess,pbLast,&Payload,sizeof(PAYLOAD_PACK),&re)) || (sizeof(PAYLOAD_PACK) != re))
            {
                continue;
            }
            if (PAYLOAD_PACK_SIGNATURE != Payload.Signature)
            {
                continue;
            }
            if (0 != memcmp(Payload.SignMD5,MD5,16))
            {
                continue;
            }
            if (mbi.RegionSize < sizeof(PAYLOAD_PACK)+Payload.DataLength)
            {
                continue;
            }
            if (DataLength)
            {
                *DataLength = Payload.DataLength;
            }
            return (PT_void)(((PPAYLOAD_PACK)pbLast)+1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }
    return NULL;
}

PT_void blpp_Payload_AddRemotePack(HANDLE hProcess,PCT_str Identity,PCT_void pData,T_Dword DataLength)
{
    T_Dword cbTotal = sizeof(PAYLOAD_PACK) + DataLength;
    PT_byte pbBase = (PT_byte)VirtualAllocEx(hProcess,NULL,cbTotal,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (NULL == pbBase)
    {
        return NULL;
    }
    SIZE_T cbWrote = 0;
    // Write data first.
    if (!WriteProcessMemory(hProcess,pbBase+sizeof(PAYLOAD_PACK),pData,DataLength,&cbWrote) || (cbWrote != DataLength))
    {
        VirtualFreeEx(hProcess,pbBase,0,MEM_RELEASE);
        return NULL;
    }
    PAYLOAD_PACK pp;
    pp.Signature = PAYLOAD_PACK_SIGNATURE;
    blpp_Hash_MD5(Identity,strlen(Identity),pp.SignMD5);
    pp.DataLength = DataLength;
    // Write head at last.
    if (!WriteProcessMemory(hProcess,pbBase,&pp,sizeof(PAYLOAD_PACK),&cbWrote) || (cbWrote != sizeof(PAYLOAD_PACK)))
    {
        VirtualFreeEx(hProcess,pbBase,0,MEM_RELEASE);
        return NULL;
    }
    return pbBase+sizeof(PAYLOAD_PACK);
}

T_bool blpp_Payload_FreeRemotePack(HANDLE hProcess,PT_void pData)
{
    return VirtualFreeEx(hProcess,((PT_byte)pData)-sizeof(PAYLOAD_PACK),0,MEM_RELEASE);
}
