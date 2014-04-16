
#include "../../basicLibPP/basicLibPP/basicLibPP.h"
#include <iostream>
#include <string>

using namespace std;

BLPP_QUEUED_LOCK lock = BLPP_QUEUED_LOCK_INIT;

DWORD WINAPI th(LPVOID pv)
{
    if (pv)
    {
        blpp_Lock_AcquireQueuedLockExclusive(&lock);
        cout<<"Ecx acquired!"<<endl;
        Sleep(500);
        cout<<"Ecx call released!"<<endl;
        blpp_Lock_ReleaseQueuedLockExclusive(&lock);
        cout<<"Ecx released!"<<endl;
    }
    else
    {
        blpp_Lock_AcquireQueuedLockShared(&lock);
        cout<<"Sha acquired!"<<endl;
        Sleep(1000);
        cout<<"Sha call released!"<<endl;
        blpp_Lock_ReleaseQueuedLockShared(&lock);
        cout<<"Sha released!"<<endl;
    }
    return 0;
}

int __cdecl sqlcall(void* lparam,int argc,char** value,char** argv)
{
    for (int i=0;i<argc;++i)
    {
        cout<<argv[i]<<" "<<value[i]<<endl;
    }
    return 0;
}

T_void __stdcall hookcall(PT_void Param,PBLPP_HOOK_INFO pInfo)
{
    if (blpp_Tls_CheckAndSetFlag(1))
    {
        cout<<"hook call esp:"<<pInfo->esp<<"                       ok!!!"<<endl;
        blpp_Tls_ClearFlag(1);
    }
}

int main()
{
    cout<<"blpp test"<<endl;
    // version
    printf("version: %d                                      ok\n",blpp_version());
    // Lock.
    /**
    out:
    Sha acquired!
    Sha acquired!
    Sha call released!
    Sha released!
    Sha call released!
    Sha released!
    Ecx acquired!
    Ecx call released!
    Ecx released!
    Sha acquired!
    Sha acquired!
    Sha call released!
    Sha released!
    Sha call released!
    Sha released!
    **/
/*
    CreateThread(0,0,th,0,0,0); // share.
    CreateThread(0,0,th,0,0,0); // share.
    Sleep(500);
    CreateThread(0,0,th,(PVOID)1,0,0); // exc.
    Sleep(100);
    CreateThread(0,0,th,0,0,0); // share.
    CreateThread(0,0,th,0,0,0); // share.
    Sleep(3000);
    system("pause");
*/
    // mm
    void *dat = blpp_mem_alloc(1000);
    cout<<"mem alloc:"<<dat<<(dat?"                              ok":"                                     err")<<endl;
    blpp_mem_free(dat);
    // hash
    unsigned char hashCode[32];
    blpp_Hash_MD5("hello",5,hashCode);
    for (int i=0;i<16;++i)
    {
        printf("%02X",hashCode[i]);
    }
    cout<<endl;
    blpp_Hash_SHA256("hello",5,hashCode,0);
    for (int i=0;i<32;++i)
    {
        printf("%02X",hashCode[i]);
    }
    cout<<endl;
    // Text.
    PWSTR wstr;
    PSTR str;
    if (blpp_TextEncode_AnsiToUnicode("hello ansi",&wstr))
    {
        printf("%S\n",wstr);
        blpp_mem_free(wstr);
    }
    if (blpp_TextEncode_UnicodeToAnsi(L"hello uni",&str))
    {
        printf("%s\n",str);
        blpp_mem_free(str);
    }
    // Verify
    BLPP_VERIFY_RESULT vr = blpp_SignVerify_VerifyFileSignA("C:\\Windows\\SysWOW64\\user32.dll");
    if (vr == VrTrusted)
    {
        cout<<"user32 verify"<<endl;
    }
    else
    {
        cout<<"user32 not verify"<<(int)vr<<endl;
    }
    vr = blpp_SignVerify_VerifyFileSignW(L"c:\\windows\\sttray64.exe");
    if (vr == VrTrusted)
    {
        cout<<"sttray64.exe verify"<<endl;
    }
    else
    {
        cout<<"sttray64.exe not verify"<<endl;
    }
    // lzma
    BLPP_LZMA_COMPRESS_REQUST lcr = {0};
    string std_str = "¾Í´òî§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯î§Ë¯";
    lcr.InputData = (PT_byte)std_str.c_str();
    lcr.InputLength = std_str.length()+1;
    lcr.CompressLevel = 8;
    T_status st = blpp_Lzma_CompressData(&lcr);
    if (T_IsSuccess(st))
    {
        cout<<"CpData ok. len:"<<lcr.CompressedLength<<" old len:"<<std_str.length()<<endl;
    }
    else
    {
        cout<<"CpData err."<<st<<endl;
    }
    BLPP_LZMA_UNCOMPRESS_REQUST lur = {0};
    lur.CompressedData = lcr.CompressedData;
    lur.CompressedLength = lcr.CompressedLength;
    st = blpp_Lzma_UncompressData(&lur);
    if (T_IsSuccess(st))
    {
        cout<<"UncpData ok. :"<<(PT_str)lur.UncompressedData<<endl;
    }
    else
    {
        cout<<"UncpData err."<<st<<endl;
    }
    blpp_mem_free(lcr.CompressedData);
    blpp_mem_free(lur.UncompressedData);
    // system.
    cout<<"cur os:"<<(int)blpp_System_GetCurrentOs()<<endl;
    cout<<"at least win7?"<<(blpp_System_IsOsAtLeast(WIN_7)?"Y":"N")<<endl;
    cout<<"at least vista?"<<(blpp_System_IsOsAtLeast(WIN_VISTA)?"Y":"N")<<endl;
    cout<<"at least win8?"<<(blpp_System_IsOsAtLeast(WIN_8)?"Y":"N")<<endl;
    cout<<"64bit?"<<(blpp_System_Is64BitOs()?"Y":"N")<<endl;
    // Obj hack.
    blpp_Object_RefreshPrefix();
    HANDLE hFile = CreateFile("C:\\windows\\system32\\ntdll.dll",GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
    OBJ_OBJECT_TYPE type;
    T_Dword refCount;
    T_wchar name[1000]={0};
    T_Dword pid,tid;
    T_bool bRet = blpp_Object_QueryHandleInfo(hFile,&type,&refCount,name,2000,&pid,&tid);
    PT_str ansi;
    blpp_TextEncode_UnicodeToAnsi(name,&ansi);
    cout<<"obj:"<<(bRet?"ok":"error")<<" refCount:"<<refCount<<" name:"<<ansi<<" type:"<<type<<endl;
    blpp_mem_free(ansi);
    CloseHandle(hFile);
    HKEY key;
    RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\services\\AFD\\Enum",NULL,KEY_READ,&key);
    cout<<"key:"<<(T_Dword)key<<endl;
    bRet = blpp_Object_QueryHandleInfo(key,&type,&refCount,name,2000,&pid,&tid);
    if (bRet)
    {
        blpp_TextEncode_UnicodeToAnsi(name,&ansi);
        cout<<"obj:"<<(bRet?"ok":"error")<<" refCount:"<<refCount<<" name:"<<ansi<<" type:"<<type<<endl;
        blpp_mem_free(ansi);
    }
    else
    {
        cout<<"gen reg key fail."<<endl;
    }
    RegCloseKey(key);
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE,FALSE,GetCurrentProcessId());
    bRet = blpp_Object_QueryHandleInfo(hProcess,&type,&refCount,name,2000,&pid,&tid);
    if (bRet)
    {
        cout<<"obj:"<<(bRet?"ok":"error")<<" refCount:"<<refCount<<" type:"<<type<<"pid:"<<pid<<" tid:"<<tid<<endl;
    }
    else
    {
        cout<<"gen reg key fail."<<endl;
    }
    CloseHandle(hProcess);
    // md5 db.
    void *db = blpp_md5Tree_New();
    if (NULL == db)
    {
        cout<<"new error."<<endl;
    }
    T_byte md5_1[16];
    T_byte data[100];
    T_Dword dalen = 100;
    blpp_Hash_MD5("he",2,md5_1);
    st = blpp_md5Tree_Insert(db,md5_1,"he data",8);
    cout<<"insert he "<<(int)st<<endl;
    blpp_Hash_MD5("ze",2,md5_1);
    st = blpp_md5Tree_Insert(db,md5_1,"ze data",8);
    cout<<"insert ze "<<(int)st<<endl;
    blpp_Hash_MD5("he",2,md5_1);
    st = blpp_md5Tree_Insert(db,md5_1,"he data",8);
    cout<<"insert he "<<(int)st<<endl;
    blpp_Hash_MD5("he",2,md5_1);
    st = blpp_md5Tree_Find(db,md5_1,data,&dalen);
    cout<<"find he "<<(int)st<<" dat:"<<data<<" len:"<<dalen<<endl;
    blpp_md5Tree_Erase(db,md5_1);
    st = blpp_md5Tree_Find(db,md5_1,data,&dalen);
    cout<<"find he "<<(int)st<<endl;
    st = blpp_md5Tree_SaveA(db,"aa.db");
    cout<<"save:"<<(int)st<<endl;
/*
    st = blpp_md5Tree_LoadW(db,L"aa.db");
    cout<<"load:"<<(int)st<<endl;
    blpp_Hash_MD5("ze",2,md5_1);
    st = blpp_md5Tree_Find(db,md5_1,data,&dalen);
    cout<<"find ze "<<(int)st<<" dat:"<<data<<" len:"<<dalen<<endl;
*/
    // Sqlite 3.
    PCT_str errStr;
    PT_void sql = blpp_sqlite_OpenDB("sql3.db",TRUE,TRUE,&errStr);
    if (NULL == sql)
    {
        cout<<"sql3 open err: "<<errStr<<endl;
    }
    char errBuffer[1024];
    bRet = blpp_sqlite_Exec(sql,"CREATE TABLE players ( ID INTEGER PRIMARY KEY, Ãû×Ö TEXT, num INTERER );",sqlcall,0,errBuffer,1024);
    if (!bRet)
    {
        cout<<errBuffer<<endl;
    }
    bRet = blpp_sqlite_Exec(sql,"INSERT INTO players (Ãû×Ö,num) VALUES('zzy','23');",sqlcall,0,errBuffer,1024);
    if (!bRet)
    {
        cout<<errBuffer<<endl;
    }
    bRet = blpp_sqlite_Exec(sql,"select * from players where Ãû×Ö = 'zzy';",sqlcall,0,errBuffer,1024);
    if (!bRet)
    {
        cout<<errBuffer<<endl;
    }
    blpp_sqlite_CloseDB(sql);
    // Disasm
    PZZY_DIS_CONTEXT ctx = DisEng_AllocateContext();
    DisEng_DECOMPOSED de;
    DisEng_SetCpuType(ctx,32);
    DisEng_Disasm(ctx,0,(T_Qword)CloseHandle,CloseHandle,NULL,&de);
    cout<<"closehandel: "<<(int)de.Opcode<<endl;
    DisEng_FreeContext(ctx);
    // Hook.
/*
    DWORD dw1,dw2,dw=0;
    dw1 = GetTickCount();
    for (int i=0;i<1000*1000*100;++i)
    {
        dw+=GetTickCount();
    }
    dw2 = GetTickCount();
    cout<<"perf t:"<<dw2-dw1<<"ms"<<endl;
*/
    blpp_Hook_AddThread(GetCurrentThreadId());
    blpp_Hook_AddAllThread();
    PT_void cookie;
    st = blpp_Hook_SetBypassFilter(GetProcAddress(GetModuleHandle("ntdll"),"NtClose"),hookcall,0,&cookie,FALSE);
    cout<<"hook st:"<<(int)st<<endl;
    bRet = blpp_Hook_StartBypassFilter(cookie);
    cout<<"start bypass "<<bRet<<endl;
    Beep(1000,200);
    blpp_Hook_StopBypassFilter(cookie);
    T_Dword fix;
    blpp_Hook_FixHook(&fix);
    cout<<"hook fix:"<<fix<<endl;
    blpp_Hook_RemoveBypassFilter(cookie);
    // Tray
    PBLPP_TRAY_CONTEXT pTray = blpp_Tray_CreateNewTray(LoadIcon(0,IDI_SHIELD),(HWND)1,1,"test tip",1009);
    Sleep(2000);
    blpp_Tray_ChangeIcon(pTray,LoadIcon(0,IDI_WARNING));
    blpp_Tray_BalloonMessage(pTray,"hello\r\ntext","title");
    Sleep(2000);
    blpp_Tray_DestoryTray(pTray);
    // pipe.
    HANDLE hPipe = blpp_Pipe_CreateNamedLinker("fsdhsjkjf",TRUE);
    cout<<"pipe handle:"<<(int)hPipe<<endl;
    blpp_Pipe_FreePipe(hPipe);
    // Payload.
    string pl_data = "payload test";
    PT_void pl = blpp_Payload_AddNativePack("txt",pl_data.c_str(),pl_data.length()+1);
    T_Dword pllen;
    PT_void pl_find = blpp_Payload_FindNativePack("txt",&pllen);
    cout<<"pl old:"<<pl<<" pl find:"<<pl_find<<" data:"<<(PT_str)pl_find<<endl;
    blpp_Payload_FreeNativePack(pl_find);
/*
    hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,6284);
    pl = blpp_Payload_AddRemotePack(hProcess,"remote",pl_data.c_str(),pl_data.length()+1);
    pl_find = blpp_Payload_FindRemotePack(hProcess,"remote",&pllen);
    cout<<"pl old:"<<pl<<" pl find:"<<pl_find<<endl;
    blpp_Payload_FreeRemotePack(hProcess,pl_find);
    CloseHandle(hProcess);
*/
    //blpp_Log_SetLogDirectory("c:\\trap");
    blpp_Log_DebugLog("hello %d,%c",2,97);
    //
    // Mem fast allocator
    //
    PBLPP_FAST_ALLOCATOR_CONTEXT mctx = blpp_mem_createFastAllocator(100,100);
    PT_void p1,p2;
    p1 = blpp_mem_allocateFromFastAllocator(mctx);
    p2 = blpp_mem_allocateFromFastAllocator(mctx);
    if (p1 && p2)
    {
        printf("%p %p                                ok\n",p1,p2);
    }
    else
    {
        printf("fast alloc                             err\n");
    }
    blpp_mem_freeToFastAllocator(mctx,p1);
    blpp_mem_freeToFastAllocator(mctx,p2);
    blpp_mem_closeFastAllocator(mctx);
    //
    // fs by pass.
    //
    HANDLE hf = blpp_fs_CreateFileBypassA("V:\\blpp_test\\Release\\bypass.txt",GENERIC_ALL,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL);
    if (INVALID_HANDLE_VALUE == hf)
    {
        printf("bypass ct file                             err\n");
    }
    else
    {
        DWORD re;
        WriteFile(hf,"hhh",3,&re,NULL);
        printf("bypass ct file %d                            ok\n",hf);
        CloseHandle(hf);
    }
    //
    // Mem file.
    //
    BLPP_MAP_FILE_STRUCT MFS;
    st = blpp_fs_LoadFileAsMemoryA("bypass.txt",&MFS,FALSE,false);
    if (!T_IsSuccess(st))
    {
        printf("mem map file                          err\n");
    }
    else
    {
        cout<<"size:"<<MFS.FileSize.QuadPart<<"  "<<(PT_str)MFS.ImageBase<<endl;
        blpp_fs_UnLoadFileMemory(&MFS);
    }
    system("pause");
    return 0;
}
