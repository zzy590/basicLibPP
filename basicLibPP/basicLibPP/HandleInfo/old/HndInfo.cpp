
#include "HndInfo.h"

#include <xstring>
#include <map>

using namespace std;

#if 1
    #undef DBG_PRINT
    #undef DBG_SHOW_WSTRING
    #define DBG_PRINT(_x)
    #define DBG_SHOW_WSTRING(_uni)
#endif

//
// Hack thread context.
//

typedef enum _OBJ_QUERY_OBJECT_WORK
{
    QueryNameHack,
    QuerySecurityHack,
    SetSecurityHack
} OBJ_QUERY_OBJECT_WORK;

typedef struct _OBJ_QUERY_OBJECT_CONTEXT
{
    BOOL Initialized;
    OBJ_QUERY_OBJECT_WORK Work;
    HANDLE Handle;
    SECURITY_INFORMATION SecurityInformation;
    PVOID Buffer;
    ULONG Length;
    NTSTATUS Status;
    ULONG ReturnLength;
} OBJ_QUERY_OBJECT_CONTEXT, *POBJ_QUERY_OBJECT_CONTEXT;

//
// Device Mup prefixes.
//

#define OBJ_DEVICE_MUP_PREFIX_NAME_LENGTH (128)
#define OBJ_DEVICE_MUP_PREFIX_NAME_SIZE (128*sizeof(WCHAR))

#define OBJ_DEVICE_MUP_PREFIX_MAX_COUNT 16

static T_Dword ObjDeviceMupPrefixesCount = 0;
static wstring ObjDeviceMupPrefixes[OBJ_DEVICE_MUP_PREFIX_MAX_COUNT];
static BLPP_QUEUED_LOCK ObjDeviceMupPrefixesLock = BLPP_QUEUED_LOCK_INIT;

//
// Device Name/GUID prefixes.
//

typedef enum _DEVICE_PREFIX_TYPE
{
    OBJ_DEVICE_NAME_PREFIX = 0,
    OBJ_DEVICE_GUID_PREFIX,
    OBJ_DEVICE_PREFIX_TYPE_COUNT,
} DEVICE_PREFIX_TYPE;

#define OBJ_MAX_DEVICE_COUNT (26)

#define OBJ_DEVICE_PREFIX_NAME_LENGTH (128)
#define OBJ_DEVICE_PREFIX_NAME_SIZE (128*sizeof(WCHAR))

static wstring ObjDosDevicePrefix[OBJ_MAX_DEVICE_COUNT][OBJ_DEVICE_PREFIX_TYPE_COUNT];
static BLPP_QUEUED_LOCK ObjDevicePrefixLock = BLPP_QUEUED_LOCK_INIT;

//
// Local value for other thread acquire.
//

static BLPP_QUEUED_LOCK ObjQueryObjectMutex = BLPP_QUEUED_LOCK_INIT;
static HANDLE ObjQueryObjectThreadHandle = NULL;
static DWORD ObjQueryObjectThreadId = 0;
static PVOID ObjQueryObjectFiber = NULL;
static HANDLE ObjQueryObjectStartEvent = NULL;
static HANDLE ObjQueryObjectCompletedEvent = NULL;
static OBJ_QUERY_OBJECT_CONTEXT ObjQueryObjectContext = {0};

//
// Map for type recognize.
//

class WideString
{
private:
    wstring m_wstr;
public:
    WideString(){}
    WideString(const wchar_t *str):m_wstr(str){}
    WideString(const wstring &str):m_wstr(str){}
    WideString(const WideString &another):m_wstr(another.m_wstr){}
    bool operator<(const WideString &another) const
    {
        size_t s1,s2;
        s1 = m_wstr.length();
        s2 = another.m_wstr.length();
        if (s1 == s2)
        {
            if (memcmp(m_wstr.data(),another.m_wstr.data(),s1) < 0)
            {
                return true;
            }
            return false;
        }
        return s1<s2;
    }
    bool operator==(const WideString &another) const
    {
        return (0==m_wstr.compare(another.m_wstr));
    }
    bool operator!=(const WideString &another) const
    {
        return (0!=m_wstr.compare(another.m_wstr));
    }
};

map<WideString,OBJ_OBJECT_TYPE> ObjTypeMap;
const static PT_wchar TypeNameList[] =
{
    L"Unknown",
    L"Adapter",
    L"ALPC_Port",
    L"Callback",
    L"Controller",
    L"DebugObject",
    L"Desktop",
    L"Device",
    L"Directory",
    L"Driver",
    L"EtwConsumer",
    L"EtwRegistration",
    L"Event",
    L"EventPair",
    L"File",
    L"FilterCommunicationPort",
    L"FilterConnectionPort",
    L"IoCompletion",
    L"IoCompletionReserve",
    L"Job",
    L"Key",
    L"KeyedEvent",
    L"Mutant",
    L"PcwObject",
    L"PowerRequest",
    L"Process",
    L"Profile",
    L"Section",
    L"Semaphore",
    L"Session",
    L"SymbolicLink",
    L"Thread",
    L"Timer",
    L"TmEn",
    L"TmRm",
    L"TmTm",
    L"TmTx",
    L"Token",
    L"TpWorkerFactory",
    L"Type",
    L"UserApcReserve",
    L"WindowStation",
    L"WmiGuid",
    NULL
};

C_ASSERT(sizeof(TypeNameList) == (OBJ_TYPE_ALL_COUNT+1)*sizeof(PT_wstr));

//
// Function.
//

static NTSTATUS ObjpGetObjectBasicInformation
(
    __in HANDLE Handle,
    __out POBJECT_BASIC_INFORMATION BasicInformation
)
{
    NTSTATUS status;
    status = NtQueryObject(Handle,ObjectBasicInformation,BasicInformation,sizeof(OBJECT_BASIC_INFORMATION),NULL);
    if (NT_SUCCESS(status))
    {
        // The object was referenced in NtQueryObject.
        // We need to subtract 1 from the pointer count.
        BasicInformation->PointerCount -= 1;
    }
    return status;
}

static NTSTATUS ObjpGetObjectTypeName
(
    __in HANDLE Handle,
    __out wstring &TypeName
)
{
    NTSTATUS status;
    POBJECT_TYPE_INFORMATION buffer;
    ULONG returnLength = 0;
    // Get the needed buffer size.
    status = NtQueryObject(Handle,ObjectTypeInformation,NULL,0,&returnLength);
    if (0 == returnLength)
    {
        return status;
    }
    buffer = (POBJECT_TYPE_INFORMATION)blpp_mem_alloc(returnLength);
    if (NULL == buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = NtQueryObject(Handle,ObjectTypeInformation,buffer,returnLength,&returnLength);
    if (!NT_SUCCESS(status))
    {
        blpp_mem_free(buffer);
        return status;
    }
    // Create a copy of the type name.
    LPWSTR tmpMem = (LPWSTR)blpp_mem_alloc(buffer->TypeName.Length+sizeof(WCHAR));
    if (NULL == tmpMem)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        memcpy(tmpMem,buffer->TypeName.Buffer,buffer->TypeName.Length);
        tmpMem[buffer->TypeName.Length/sizeof(WCHAR)] = 0;
        TypeName = tmpMem;
        blpp_mem_free(tmpMem);
    }
    blpp_mem_free(buffer);
    return status;
}

static NTSTATUS ObjpGetObjectName
(
    __in HANDLE Handle,
    __out wstring &ObjectName
)
{
    NTSTATUS status;
    POBJECT_NAME_INFORMATION buffer;
    ULONG needSize;
    ULONG attempts = 4;
    needSize = 0x200;
    buffer = (POBJECT_NAME_INFORMATION)blpp_mem_alloc(needSize);
    if (NULL == buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // A loop is needed because the I/O subsystem likes to give us the wrong return lengths...
    do
    {
        status = NtQueryObject(Handle,ObjectNameInformation,buffer,needSize,&needSize);
        if ((STATUS_BUFFER_OVERFLOW == status) || (STATUS_INFO_LENGTH_MISMATCH == status) || (STATUS_BUFFER_TOO_SMALL == status))
        {
            blpp_mem_free(buffer);
            needSize += 0x200;
            buffer = (POBJECT_NAME_INFORMATION)blpp_mem_alloc(needSize);
            if (NULL == buffer)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        else
        {
            break;
        }
    } while (--attempts);
    if (NT_SUCCESS(status))
    {
        PWSTR tmpMem = (PWSTR)blpp_mem_alloc(buffer->Name.Length+sizeof(WCHAR));
        if (NULL == tmpMem)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            memcpy(tmpMem,buffer->Name.Buffer,buffer->Name.Length);
            tmpMem[buffer->Name.Length/sizeof(WCHAR)] = 0;
            ObjectName = tmpMem;
            blpp_mem_free(tmpMem);
        }
    }
    blpp_mem_free(buffer);
    return status;
}

static inline NTSTATUS ObjSidToStringSid
(
    __in PSID Sid,
    __in PWSTR StringBuffer,
    __in DWORD BufferSize
)
{
    UNICODE_STRING us;
    us.MaximumLength = (USHORT)BufferSize;
    us.Length = 0;
    us.Buffer = StringBuffer;
    return RtlConvertSidToUnicodeString(&us,Sid,FALSE);
}

static NTSTATUS ObjpQueryTokenVariableSize
(
    __in HANDLE TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __out PVOID *Buffer
)
{
    NTSTATUS status;
    PVOID buffer;
    ULONG returnLength = 0;
    status = NtQueryInformationToken(TokenHandle,TokenInformationClass,NULL,0,&returnLength);
    if (0 == returnLength)
    {
        return status;
    }
    buffer = blpp_mem_alloc(returnLength);
    if (NULL == buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = NtQueryInformationToken(TokenHandle,TokenInformationClass,buffer,returnLength,&returnLength);
    if (NT_SUCCESS(status))
    {
        *Buffer = buffer;
    }
    else
    {
        blpp_mem_free(buffer);
    }
    return status;
}

static inline HANDLE ObjpGetToken()
{
    HANDLE tokenHandle;
    if (NT_SUCCESS(NtOpenProcessToken(NtCurrentProcess(),TOKEN_QUERY,&tokenHandle)))
    {
        return tokenHandle;
    }
    return NULL;
}

const static T_byte _mapCaseTable[128] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z',  0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z',  0x7B, 0x7C, 0x7D, 0x7E, 0x7F
};

static bool isStartWithStringW(const wstring &str,const wstring &head,bool bIgnoreCase)
{
    PCWSTR pCheck = str.data();
    PCWSTR pHead = head.data();
    size_t len = head.length();
    if (str.length() < len)
    {
        return false;
    }
    if (bIgnoreCase)
    {
        for (T_Dword i=0;i<len;++i)
        {
            if (pCheck[i]<128 && pHead[i]<128)
            {
                if (_mapCaseTable[pCheck[i]] != _mapCaseTable[pHead[i]])
                {
                    return false;
                }
            }
            else if (pCheck[i] != pHead[i])
            {
                return false;
            }
        }
    }
    else
    {
        for (T_Dword i=0;i<len;++i)
        {
            if (pCheck[i] != pHead[i])
            {
                return false;
            }
        }
    }
    return true;
}

bool ObjFormatNativeKeyName
(
    __inout wstring &Name
)
{
    const static wstring hklmPrefix = L"\\Registry\\Machine";
    const static wstring hkcrPrefix = L"\\Registry\\Machine\\Software\\Classes";
    const static wstring hkuPrefix = L"\\Registry\\User";
    static wstring hkcuPrefix;
    static wstring hkcucrPrefix;
    // Fix string.
    const static wstring hklmString = L"HKLM";
    const static wstring hkcrString = L"HKCR";
    const static wstring hkuString = L"HKU";
    const static wstring hkcuString = L"HKCU";
    const static wstring hkcucrString = L"HKCU\\Software\\Classes";
    // Mark
    static bool inited = false;
    if (!inited)
    {
        HANDLE Token;
        PTOKEN_USER tokenUser;
        WCHAR stringSid[MAX_PATH] = {0};
        Token = ObjpGetToken();
        if (Token)
        {
            if (NT_SUCCESS(ObjpQueryTokenVariableSize(Token,TokenUser,(PVOID *)&tokenUser)))
            {
                ObjSidToStringSid(tokenUser->User.Sid,stringSid,MAX_PATH*sizeof(WCHAR));
                blpp_mem_free(tokenUser);
            }
            NtClose(Token);
        }
        if (stringSid[0])
        {
            const static PWSTR registryUserPrefix = L"\\Registry\\User\\";
            const static PWSTR classesString = L"_Classes";
            hkcuPrefix.append(registryUserPrefix);
            hkcuPrefix.append(stringSid);
            hkcucrPrefix.append(hkcuPrefix);
            hkcucrPrefix.append(classesString);
        }
        else
        {
            hkcuPrefix = L"...";
            hkcucrPrefix = L"...";
        }
        inited = true;
    }
    if (isStartWithStringW(Name,hkcrPrefix,true))
    {
        Name.replace(0,hkcrPrefix.length(),hkcrString);
    }
    else if (isStartWithStringW(Name,hklmPrefix,true))
    {
        Name.replace(0,hklmPrefix.length(),hklmString);
    }
    else if (isStartWithStringW(Name,hkcucrPrefix,true))
    {
        Name.replace(0,hkcucrPrefix.length(),hkcucrString);
    }
    else if (isStartWithStringW(Name,hkcuPrefix,true))
    {
        Name.replace(0,hkcuPrefix.length(),hkcuString);
    }
    else if (isStartWithStringW(Name,hkuPrefix,true))
    {
        Name.replace(0,hkuPrefix.length(),hkuString);
    }
    else
    {
        return false;
    }
    return true;
}

void ObjUpdateDosDevicePrefixes()
{
    WCHAR deviceNameBuffer[7] = L"\\??\\ :";
    WCHAR volumeNameBuffer[4] = L" :\\";
    WCHAR TmpName[OBJ_DEVICE_PREFIX_NAME_LENGTH];
    ULONG i;
    for (i = 0; i < OBJ_MAX_DEVICE_COUNT; ++i)
    {
        HANDLE linkHandle;
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING deviceName;
        deviceNameBuffer[4] = (WCHAR)('A' + i);
        volumeNameBuffer[0] = (WCHAR)('A' + i);
        deviceName.Buffer = deviceNameBuffer;
        deviceName.Length = 6 * sizeof(WCHAR);
        InitializeObjectAttributes(&oa,&deviceName,OBJ_CASE_INSENSITIVE,NULL,NULL);
        if (NT_SUCCESS(NtOpenSymbolicLinkObject(&linkHandle,SYMBOLIC_LINK_QUERY,&oa)))
        {
            AutoQueuedLock al(ObjDevicePrefixLock,true);
            if (GetVolumeNameForVolumeMountPointW(volumeNameBuffer,TmpName,OBJ_DEVICE_PREFIX_NAME_LENGTH))
            {
                /** "\\?\Volume{GUID}\" **/
                if ((L'\\' == TmpName[0]) &&
                    (L'\\' == TmpName[1]) &&
                    (L'?'  == TmpName[2]) &&
                    (L'\\' == TmpName[3]))
                {
                    if (TmpName[4])
                    {
                        ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX] = &TmpName[4];
                        size_t len = ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX].length();
                        if ('\\' == ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX][len-1])
                        {
                            ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX].erase(len-1,1);
                        }
                        DBG_PRINT("get guid:");
                        DBG_SHOW_WSTRING(ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX].c_str());
                    }
                }
            }
            // Now device name prefix.
            deviceName.MaximumLength = OBJ_DEVICE_PREFIX_NAME_SIZE;
            deviceName.Length = 0;
            deviceName.Buffer = TmpName;
            if (NT_SUCCESS(NtQuerySymbolicLinkObject(linkHandle,&deviceName,NULL)))
            {
                if (deviceName.Length < OBJ_DEVICE_PREFIX_NAME_SIZE)
                {
                    deviceName.Buffer[deviceName.Length/sizeof(WCHAR)] = 0;
                    ObjDosDevicePrefix[i][OBJ_DEVICE_NAME_PREFIX] = deviceName.Buffer;
                    DBG_PRINT("get dev name:");
                    DBG_SHOW_WSTRING(ObjDosDevicePrefix[i][OBJ_DEVICE_NAME_PREFIX].c_str());
                }
            }
            NtClose(linkHandle);
        }
    }
}

void ObjUpdateMupDevicePrefixes()
{
    const static PT_str orderKeyName = "System\\CurrentControlSet\\Control\\NetworkProvider\\Order";
    const static PT_str servicesStringPart = "System\\CurrentControlSet\\Services\\";
    const static PT_str networkProviderStringPart = "\\NetworkProvider";
    DWORD Type;
    PT_str providerOrder;
    T_Dword providerOrderSize = 1024;
    PT_str pStart,pEnd;
    // The provider names are stored in the ProviderOrder value in this key:
    // HKLM\System\CurrentControlSet\Control\NetworkProvider\Order
    // Each name can then be looked up, its device name in the DeviceName value in:
    // HKLM\System\CurrentControlSet\Services\<ProviderName>\NetworkProvider
    // Note that we assume the providers only claim their device name. Some providers
    // such as DFS claim an extra part, and are not resolved correctly here.
    providerOrder = (PT_str)blpp_mem_alloc(providerOrderSize+sizeof(T_char));
    if (NULL == providerOrder)
    {
        return;
    }
    if (!blpp_System_GetRegDataA(HKEY_LOCAL_MACHINE,orderKeyName,"ProviderOrder",(PT_byte)providerOrder,&providerOrderSize,&Type))
    {
        // Small?
        blpp_mem_free(providerOrder);
        providerOrder = (PT_str)blpp_mem_alloc(providerOrderSize+sizeof(T_char));
        if (NULL == providerOrder)
        {
            return;
        }
        if (!blpp_System_GetRegDataA(HKEY_LOCAL_MACHINE,orderKeyName,"ProviderOrder",(PT_byte)providerOrder,&providerOrderSize,&Type))
        {
            blpp_mem_free(providerOrder);
            return;
        }
    }
    if (REG_SZ != Type && REG_MULTI_SZ != Type && REG_EXPAND_SZ != Type)
    {
        blpp_mem_free(providerOrder);
        return;
    }
    providerOrder[providerOrderSize] = 0;
    DBG_PRINT("get providerOrder:"<<providerOrder);
    if (0 == providerOrder[0])
    {
        blpp_mem_free(providerOrder);
        return;
    }
    // Now lock and analysis providerOrder.
    AutoQueuedLock al(ObjDeviceMupPrefixesLock,true);
    for (T_Dword i=0;i<ObjDeviceMupPrefixesCount;++i)
    {
        ObjDeviceMupPrefixes[i].clear();
    }
    ObjDeviceMupPrefixesCount = 0;
    ObjDeviceMupPrefixes[ObjDeviceMupPrefixesCount++] = L"\\Device\\Mup";
    if (blpp_System_IsOsAtLeast(WIN_VISTA))
    {
        ObjDeviceMupPrefixes[ObjDeviceMupPrefixesCount++] = L"\\Device\\DfsClient";
    }
    else
    {
        ObjDeviceMupPrefixes[ObjDeviceMupPrefixesCount++] = L"\\Device\\WinDfs";
    }
    pEnd = NULL;
    pStart = providerOrder;
    while (pStart)
    {
        T_char partName[Config_MAX_PATH];
        if (OBJ_DEVICE_MUP_PREFIX_MAX_COUNT == ObjDeviceMupPrefixesCount)
        {
            break;
        }
        pEnd = strchr(pStart,',');
        if (pEnd)
        {
            if (pEnd-pStart < Config_MAX_PATH)
            {
                memcpy(partName,pStart,pEnd-pStart);
                partName[pEnd-pStart] = 0;
            }
            else
            {
                partName[0] = 0;
            }
        }
        else
        {
            size_t len = strlen(pStart);
            if (len < Config_MAX_PATH)
            {
                memcpy(partName,pStart,len+1);
            }
            else
            {
                partName[0] = 0;
            }
        }
        if (partName[0])
        {
            string serviceKeyName;
            serviceKeyName.append(servicesStringPart);
            serviceKeyName.append(partName);
            serviceKeyName.append(networkProviderStringPart);
            T_char DevName[OBJ_DEVICE_MUP_PREFIX_NAME_LENGTH+1];
            T_Dword DevNameLen = OBJ_DEVICE_MUP_PREFIX_NAME_LENGTH;
            if (blpp_System_GetRegDataA(HKEY_LOCAL_MACHINE,(PT_str)serviceKeyName.c_str(),"DeviceName",(PT_byte)DevName,&DevNameLen,&Type))
            {
                if (REG_SZ != Type && REG_MULTI_SZ != Type && REG_EXPAND_SZ != Type)
                {
                    DevName[0] = 0;
                }
                else
                {
                    DevName[DevNameLen] = 0;
                }
            }
            else
            {
                DevName[0] = 0;
            }
            if (DevName[0])
            {
                DBG_PRINT("get net provider dev:"<<DevName);
                PT_wstr pwstr;
                if (blpp_TextEncode_AnsiToUnicode(DevName,&pwstr))
                {
                    ObjDeviceMupPrefixes[ObjDeviceMupPrefixesCount++] = pwstr;
                    blpp_mem_free(pwstr);
                }
            }
        }
        if (pEnd)
        {
            pStart = pEnd + 1;
        }
        else
        {
            break;
        }
    }
    blpp_mem_free(providerOrder);
}

bool ObjResolveDevicePrefix
(
    __inout wstring &Name
)
{
    T_Dword i;
    // Go through the DOS devices and try to find a matching prefix.
    for (i = 0; i < OBJ_MAX_DEVICE_COUNT; ++i)
    {
        bool isPrefix = false;
        size_t len;
        LOCK_AcquireQueuedLockShared(&ObjDevicePrefixLock);
        if (!ObjDosDevicePrefix[i][OBJ_DEVICE_NAME_PREFIX].empty())
        {
            if (isStartWithStringW(Name,ObjDosDevicePrefix[i][OBJ_DEVICE_NAME_PREFIX],true))
            {
                len = ObjDosDevicePrefix[i][OBJ_DEVICE_NAME_PREFIX].length();
                if (Name.length()==len || '\\'==Name[len])
                {
                    isPrefix = true;
                }
            }
        }
        LOCK_ReleaseQueuedLockShared(&ObjDevicePrefixLock);
        if (isPrefix)
        {
            // <letter>:path
            WCHAR DevLetter[] = L" :";
            DevLetter[0] = (WCHAR)(L'A' + i);
            Name.replace(0,len,DevLetter);
            return true;
        }
    }
    // Resolve network providers.
    LOCK_AcquireQueuedLockShared(&ObjDeviceMupPrefixesLock);
    for (i = 0; i < ObjDeviceMupPrefixesCount; ++i)
    {
        bool isPrefix = false;
        size_t len;
        if (!ObjDeviceMupPrefixes[i].empty())
        {
            if (isStartWithStringW(Name,ObjDeviceMupPrefixes[i],true))
            {
                len = ObjDeviceMupPrefixes[i].length();
                if (Name.length()>len && '\\'==Name[len])
                {
                    isPrefix = true;
                }
            }
        }
        if (isPrefix)
        {
            // \path
            Name.replace(0,len,L"\\");
            LOCK_ReleaseQueuedLockShared(&ObjDeviceMupPrefixesLock);
            return true;
        }
    }
    LOCK_ReleaseQueuedLockShared(&ObjDeviceMupPrefixesLock);
    return false;
}

bool ObjGetFileName
(
    __inout wstring &Name
)
{
    static WCHAR WindowsPath[MAX_PATH];
    static bool Inited = false;
    if (!Inited)
    {
        DWORD WinPathLength = 0;
        WinPathLength = GetWindowsDirectoryW(WindowsPath,MAX_PATH);
        if (0==WinPathLength || WinPathLength>=MAX_PATH)
        {
            return false;
        }
        WindowsPath[WinPathLength] = 0;
        Inited = true;
    }
    const static wstring simpleHeader = L"\\??\\";
    const static wstring windowsPrefix = L"\\Windows";
    const static wstring sysRootPrefix = L"\\SystemRoot";
    if (isStartWithStringW(Name,simpleHeader,false))
    {
        size_t len = simpleHeader.length();
        wstring bareName = Name.c_str()+len;
        if (bareName.length()>=2 && L':'!=bareName[1])
        {
            //
            // May \??\Volume{7603f260-142a-11d4-ac67-806d6172696f}.
            //
            T_Dword i;
            for (i = 0; i < OBJ_MAX_DEVICE_COUNT; ++i)
            {
                bool isPrefix = false;
                LOCK_AcquireQueuedLockShared(&ObjDevicePrefixLock);
                if (!ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX].empty())
                {
                    if (isStartWithStringW(bareName,ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX],true))
                    {
                        len = ObjDosDevicePrefix[i][OBJ_DEVICE_GUID_PREFIX].length();
                        if (bareName.length()==len || '\\'==bareName[len])
                        {
                            isPrefix = true;
                        }
                    }
                }
                LOCK_ReleaseQueuedLockShared(&ObjDevicePrefixLock);
                if (isPrefix)
                {
                    // <letter>:path
                    WCHAR DevLetter[] = L" :";
                    DevLetter[0] = (WCHAR)(L'A' + i);
                    bareName.replace(0,len,DevLetter);
                    Name = bareName;
                    return true;
                }
            }
        }
        Name = bareName;
    }
    else if (isStartWithStringW(Name,windowsPrefix,true))
    {
        Name.replace(0,windowsPrefix.length(),WindowsPath);
    }
    else if (isStartWithStringW(Name,sysRootPrefix,true))
    {
        Name.replace(0,sysRootPrefix.length(),WindowsPath);
    }
    else
    {
        return ObjResolveDevicePrefix(Name);
    }
    return true;
}

static NTSTATUS ObjpGetBestObjectName
(
    __in HANDLE Handle,
    __in OBJ_OBJECT_TYPE Type,
    __inout wstring &ObjectName,
    __out PCLIENT_ID ClientId
)
{
    //
    // Init.
    //
    static bool inited = false;
    static DWORD ProcessQueryAccess = PROCESS_QUERY_INFORMATION;
    static DWORD ThreadQueryAccess = THREAD_QUERY_INFORMATION;
    if (!inited)
    {
        if (blpp_System_IsOsAtLeast(WIN_VISTA))
        {
            ProcessQueryAccess = PROCESS_QUERY_LIMITED_INFORMATION;
            ThreadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
        }
        inited = true;
    }
    NTSTATUS status;
    ClientId->UniqueProcess = 0;
    ClientId->UniqueThread = 0;
    switch (Type)
    {
    case OBJ_TYPE_File:
        if (!ObjectName.empty())
        {
            ObjResolveDevicePrefix(ObjectName);
        }
        break;
    case OBJ_TYPE_Key:
        if (!ObjectName.empty())
        {
            ObjFormatNativeKeyName(ObjectName);
        }
        break;
    case OBJ_TYPE_Process:
    {
        HANDLE DumpHandle;
        PROCESS_BASIC_INFORMATION basicInfo;
        if (!DuplicateHandle(GetCurrentProcess(),Handle,GetCurrentProcess(),&DumpHandle,ProcessQueryAccess,FALSE,0))
        {
            return STATUS_ACCESS_DENIED;
        }
        status = NtQueryInformationProcess(DumpHandle,ProcessBasicInformation,&basicInfo,sizeof(PROCESS_BASIC_INFORMATION),NULL);
        CloseHandle(DumpHandle);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ClientId->UniqueProcess = (HANDLE)basicInfo.UniqueProcessId;
        ClientId->UniqueThread = 0;
        break;
    }
    case OBJ_TYPE_Thread:
    {
        HANDLE DumpHandle;
        THREAD_BASIC_INFORMATION basicInfo;
        if (!DuplicateHandle(GetCurrentProcess(),Handle,GetCurrentProcess(),&DumpHandle,ThreadQueryAccess,FALSE,0))
        {
            return STATUS_ACCESS_DENIED;
        }
        status = NtQueryInformationThread(DumpHandle,ThreadBasicInformation,&basicInfo,sizeof(THREAD_BASIC_INFORMATION),NULL);
        CloseHandle(DumpHandle);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ClientId->UniqueProcess = basicInfo.ClientId.UniqueProcess;
        ClientId->UniqueThread = basicInfo.ClientId.UniqueThread;
        break;
    }
    default:
        break;
    }
    return STATUS_SUCCESS;
}

static DWORD WINAPI ObjpQueryObjectThreadStart(__in PVOID Parameter)
{
    //
    // Add into internal thread.
    //
    LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
    blpp_internalThreadSet.insert(GetCurrentThreadId());
    LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
    ObjQueryObjectFiber = ConvertThreadToFiber(NULL);
    while (true)
    {
        // Wait for work.
        if (STATUS_WAIT_0 != WaitForSingleObject(ObjQueryObjectStartEvent,INFINITE))
        {
            continue;
        }
        // Make sure we actually have work.
        if (ObjQueryObjectContext.Initialized)
        {
            switch (ObjQueryObjectContext.Work)
            {
            case QueryNameHack:
                ObjQueryObjectContext.Status = NtQueryObject(
                                                   ObjQueryObjectContext.Handle,
                                                   ObjectNameInformation,
                                                   ObjQueryObjectContext.Buffer,
                                                   ObjQueryObjectContext.Length,
                                                   &ObjQueryObjectContext.ReturnLength
                                               );
                break;
            case QuerySecurityHack:
                ObjQueryObjectContext.Status = NtQuerySecurityObject(
                                                   ObjQueryObjectContext.Handle,
                                                   ObjQueryObjectContext.SecurityInformation,
                                                   (PSECURITY_DESCRIPTOR)ObjQueryObjectContext.Buffer,
                                                   ObjQueryObjectContext.Length,
                                                   &ObjQueryObjectContext.ReturnLength
                                               );
                break;
            case SetSecurityHack:
                ObjQueryObjectContext.Status = NtSetSecurityObject(
                                                   ObjQueryObjectContext.Handle,
                                                   ObjQueryObjectContext.SecurityInformation,
                                                   (PSECURITY_DESCRIPTOR)ObjQueryObjectContext.Buffer
                                               );
                break;
            default:
                ObjQueryObjectContext.Status = STATUS_NOT_SUPPORTED;
                ObjQueryObjectContext.ReturnLength = 0;
                break;
            }
            // Work done.
            SetEvent(ObjQueryObjectCompletedEvent);
        }
    }
    return 0;
}

static bool ObjpHeadQueryObjectHack()
{
    LOCK_AcquireQueuedLockExclusive(&ObjQueryObjectMutex);
    // Create a query thread if we don't have one.
    if (NULL == ObjQueryObjectThreadHandle)
    {
        ObjQueryObjectThreadHandle = CreateThread(NULL,0,ObjpQueryObjectThreadStart,NULL,0,&ObjQueryObjectThreadId);
        if (NULL == ObjQueryObjectThreadHandle)
        {
            LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
            return false;
        }
    }
    // Create the events if they don't exist.
    if (NULL == ObjQueryObjectStartEvent)
    {
        if (NULL == (ObjQueryObjectStartEvent=CreateEvent(NULL,FALSE,FALSE,NULL)))
        {
            LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
            return false;
        }
    }
    if (NULL == ObjQueryObjectCompletedEvent)
    {
        if (NULL == (ObjQueryObjectCompletedEvent=CreateEvent(NULL,FALSE,FALSE,NULL)))
        {
            LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
            return false;
        }
    }
    return true;
}

static NTSTATUS ObjpTailQueryObjectHack(__out_opt PULONG ReturnLength)
{
    DWORD waitRet;
    ObjQueryObjectContext.Initialized = TRUE;
    // Allow the worker thread to start.
    SetEvent(ObjQueryObjectStartEvent);
    // Wait for the work to complete, with a timeout of 1 second.
    waitRet = WaitForSingleObject(ObjQueryObjectCompletedEvent,1000);
    ObjQueryObjectContext.Initialized = FALSE;
    // Return normally if the work was completed.
    if (STATUS_WAIT_0 == waitRet)
    {
        NTSTATUS status;
        ULONG returnLength;
        status = ObjQueryObjectContext.Status;
        returnLength = ObjQueryObjectContext.ReturnLength;
        LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
        if (ReturnLength)
        {
            *ReturnLength = returnLength;
        }
        return status;
    }
    // Kill the worker thread if it took too long.
    // else if (waitRet == STATUS_TIMEOUT)
    else
    {
        // Kill the thread.
        if (!TerminateThread(ObjQueryObjectThreadHandle,~0u))
        {
            // Again.
            TerminateThread(ObjQueryObjectThreadHandle,~0u);
        }
        ObjQueryObjectThreadHandle = NULL;
        // Delete the fiber (and free the thread stack).
        if (ObjQueryObjectFiber)
        {
            DeleteFiber(ObjQueryObjectFiber);
            ObjQueryObjectFiber = NULL;
        }
        LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
        // Clean the internal thread.
        LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
        blpp_internalThreadSet.erase(ObjQueryObjectThreadId);
        LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
        return STATUS_UNSUCCESSFUL;
    }
}

static NTSTATUS ObjQueryObjectNameHack
(
    __in HANDLE Handle,
    __out_bcount(ObjectNameInformationLength) POBJECT_NAME_INFORMATION ObjectNameInformation,
    __in ULONG ObjectNameInformationLength,
    __out_opt PULONG ReturnLength
)
{
    if (!ObjpHeadQueryObjectHack())
    {
        return STATUS_UNSUCCESSFUL;
    }
    ObjQueryObjectContext.Work = QueryNameHack;
    ObjQueryObjectContext.Handle = Handle;
    ObjQueryObjectContext.Buffer = ObjectNameInformation;
    ObjQueryObjectContext.Length = ObjectNameInformationLength;
    return ObjpTailQueryObjectHack(ReturnLength);
}

static NTSTATUS ObjQueryObjectSecurityHack
(
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __out_opt PULONG ReturnLength
)
{
    if (!ObjpHeadQueryObjectHack())
    {
        return STATUS_UNSUCCESSFUL;
    }
    ObjQueryObjectContext.Work = QuerySecurityHack;
    ObjQueryObjectContext.Handle = Handle;
    ObjQueryObjectContext.SecurityInformation = SecurityInformation;
    ObjQueryObjectContext.Buffer = Buffer;
    ObjQueryObjectContext.Length = Length;
    return ObjpTailQueryObjectHack(ReturnLength);
}

static NTSTATUS ObjSetObjectSecurityHack
(
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __in PVOID Buffer
)
{
    if (!ObjpHeadQueryObjectHack())
    {
        return STATUS_UNSUCCESSFUL;
    }
    ObjQueryObjectContext.Work = SetSecurityHack;
    ObjQueryObjectContext.Handle = Handle;
    ObjQueryObjectContext.SecurityInformation = SecurityInformation;
    ObjQueryObjectContext.Buffer = Buffer;
    return ObjpTailQueryObjectHack(NULL);
}

NTSTATUS ObjGetHandleInformation
(
    __in HANDLE Handle,
    __out_opt POBJECT_BASIC_INFORMATION BasicInformation,
    __out_opt OBJ_OBJECT_TYPE *ObjType,
    __out wstring &TypeName,
    __out wstring &BestObjectName,
    __out_opt PCLIENT_ID BestId
)
{
    NTSTATUS status;
    OBJ_OBJECT_TYPE TypeEnum;
    CLIENT_ID ClientId;
    //
    // If get basic info;
    //
    if (BasicInformation)
    {
        status = ObjpGetObjectBasicInformation(Handle,BasicInformation);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    // Get the type name.
    status = ObjpGetObjectTypeName(Handle,TypeName);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    // Decode type
    map<WideString,OBJ_OBJECT_TYPE>::const_iterator it = ObjTypeMap.find(TypeName);
    if (it != ObjTypeMap.end())
    {
        TypeEnum = it->second;
    }
    else
    {
        TypeEnum = OBJ_TYPE_Unknown;
    }
    if (ObjType)
    {
        *ObjType = TypeEnum;
    }
    if (OBJ_TYPE_File == TypeEnum)
    {
        // 0: Query normally.
        // 1: Hack.
        // 2: Fail.
        ULONG hackLevel = 1;
        // We can't use the hack on XP because hanging threads
        // can't even be terminated!
        // But I'd like to try.
        switch (hackLevel)
        {
        case 0:
            status = ObjpGetObjectName(Handle,BestObjectName);
            break;
        case 1:
            {
                POBJECT_NAME_INFORMATION buffer;
                buffer = (POBJECT_NAME_INFORMATION)blpp_mem_alloc(0x800);
                if (NULL == buffer)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
                else
                {
                    status = ObjQueryObjectNameHack(Handle,buffer,0x800,NULL);
                    if (NT_SUCCESS(status))
                    {
                        PT_wstr tmpMem = (PT_wstr)blpp_mem_alloc(buffer->Name.Length+sizeof(WCHAR));
                        if (NULL == tmpMem)
                        {
                            status = STATUS_INSUFFICIENT_RESOURCES;
                        }
                        else
                        {
                            memcpy(tmpMem,buffer->Name.Buffer,buffer->Name.Length);
                            tmpMem[buffer->Name.Length/sizeof(WCHAR)] = 0;
                            BestObjectName = tmpMem;
                            blpp_mem_free(tmpMem);
                        }
                    }
                    blpp_mem_free(buffer);
                }
            }
            break;
        default:
            status = STATUS_NOT_SUPPORTED;
            break;
        }
    }
    else
    {
        // Query the object normally.
        status = ObjpGetObjectName(Handle,BestObjectName);
    }
    if (!NT_SUCCESS(status))
    {
        BestObjectName.clear();
    }
    if (NULL == BestId)
    {
        BestId = &ClientId;
    }
    status = ObjpGetBestObjectName(Handle,TypeEnum,BestObjectName,BestId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return STATUS_SUCCESS;
}

void ObjInit()
{
    // Insert type map.
    for (T_Dword i=0;TypeNameList[i];++i)
    {
        ObjTypeMap.insert(pair<wstring,OBJ_OBJECT_TYPE>(TypeNameList[i],(OBJ_OBJECT_TYPE)i));
    }
    // Init other.
    ObjUpdateDosDevicePrefixes();
    ObjUpdateMupDevicePrefixes();
    ObjFormatNativeKeyName(wstring(L""));
    ObjGetFileName(wstring(L""));
}

void ObjUninit()
{
    // Free the thread.
    LOCK_AcquireQueuedLockExclusive(&ObjQueryObjectMutex);
    if (ObjQueryObjectThreadHandle)
    {
        TerminateThread(ObjQueryObjectThreadHandle,~0u);
        ObjQueryObjectThreadHandle = NULL;
    }
    if (ObjQueryObjectFiber)
    {
        DeleteFiber(ObjQueryObjectFiber);
        ObjQueryObjectFiber = NULL;
    }
    if (ObjQueryObjectStartEvent)
    {
        CloseHandle(ObjQueryObjectStartEvent);
        ObjQueryObjectStartEvent = NULL;
    }
    if (ObjQueryObjectCompletedEvent)
    {
        CloseHandle(ObjQueryObjectCompletedEvent);
        ObjQueryObjectCompletedEvent = NULL;
    }
    LOCK_ReleaseQueuedLockExclusive(&ObjQueryObjectMutex);
    // Clean the internal thread.
    LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
    blpp_internalThreadSet.erase(ObjQueryObjectThreadId);
    LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
}
