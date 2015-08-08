
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

#define OBJ_QUERY_HACK_MAX_THREADS 20

typedef void(*PUSER_ROUTINE)(LPVOID lparam);

typedef struct _OBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT
{
	SLIST_ENTRY ListEntry;

	PUSER_ROUTINE Routine;
	PVOID Context;

	HANDLE StartEventHandle;
	HANDLE CompletedEventHandle;

	HANDLE ThreadHandle;
	DWORD ThreadId;
	PVOID Fiber;
} OBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT, *POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT;

typedef enum _OBJ_QUERY_OBJECT_WORK
{
	NtQueryObjectWork,
	NtQuerySecurityObjectWork,
	NtSetSecurityObjectWork
} OBJ_QUERY_OBJECT_WORK;

typedef struct _OBJ_QUERY_OBJECT_COMMON_CONTEXT
{
	OBJ_QUERY_OBJECT_WORK Work;
	NTSTATUS Status;

	union
	{
		struct
		{
			HANDLE Handle;
			OBJECT_INFORMATION_CLASS ObjectInformationClass;
			PVOID ObjectInformation;
			ULONG ObjectInformationLength;
			PULONG ReturnLength;
		} NtQueryObject;
		struct
		{
			HANDLE Handle;
			SECURITY_INFORMATION SecurityInformation;
			PSECURITY_DESCRIPTOR SecurityDescriptor;
			ULONG Length;
			PULONG LengthNeeded;
		} NtQuerySecurityObject;
		struct
		{
			HANDLE Handle;
			SECURITY_INFORMATION SecurityInformation;
			PSECURITY_DESCRIPTOR SecurityDescriptor;
		} NtSetSecurityObject;
	} u;
} OBJ_QUERY_OBJECT_COMMON_CONTEXT, *POBJ_QUERY_OBJECT_COMMON_CONTEXT;

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
// Local value for async threads.
//

static bool ObjCallWithTimeoutThreadInited = false;
static SLIST_HEADER ObjCallWithTimeoutThreadListHead = {0};
static HANDLE ObjThreadReleaseEvent = NULL;
static BLPP_QUEUED_LOCK ObjAcquireThreadLock = BLPP_QUEUED_LOCK_INIT;

//
// Map for type recognize.
//

static map<wstring,OBJ_OBJECT_TYPE> ObjTypeMap;
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
    L"WmiGuid"
};

C_ASSERT(sizeof(TypeNameList) == OBJ_TYPE_ALL_COUNT*sizeof(PT_wstr));

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
    __out wstring& TypeName,
	__out OBJ_OBJECT_TYPE& objType
)
{
	static PT_void inited = NULL;
	if (blpp_initOnce(&inited))
	{
		for (int i = 0; i < OBJ_TYPE_ALL_COUNT; ++i)
		{
			ObjTypeMap.insert(pair<wstring, OBJ_OBJECT_TYPE>(TypeNameList[i], (OBJ_OBJECT_TYPE)i));
		}
	}
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
    if (NT_SUCCESS(status))
    {
		TypeName = wstring(buffer->TypeName.Buffer, buffer->TypeName.Length / sizeof(WCHAR));
		// Decode type
		map<wstring, OBJ_OBJECT_TYPE>::const_iterator cit = ObjTypeMap.find(TypeName);
		if (cit != ObjTypeMap.end())
		{
			objType = cit->second;
		}
		else
		{
			objType = OBJ_TYPE_Unknown;
		}
    }
	blpp_mem_free(buffer);
	return status;
}

//
// Hack.
//

static POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT ObjAcquireCallWithTimeoutThread()
{
	static PT_void inited = NULL;

	if (blpp_initOnce(&inited))
	{
		if (NULL == ObjThreadReleaseEvent)
		{
			ObjThreadReleaseEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
			if (NULL == ObjThreadReleaseEvent)
			{
				blpp_initError(&inited);
				return NULL;
			}
		}
		RtlInitializeSListHead(&ObjCallWithTimeoutThreadListHead);
		for (int i = 0; i < OBJ_QUERY_HACK_MAX_THREADS; ++i)
		{
			POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT threadContext = (POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT)blpp_mem_alloc(sizeof(OBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT));
			if (threadContext != NULL)
			{
				RtlInterlockedPushEntrySList(&ObjCallWithTimeoutThreadListHead, &threadContext->ListEntry);
			}
		}
		ObjCallWithTimeoutThreadInited = true;
	}

	PSLIST_ENTRY listEntry;

	{
		AutoQueuedLock al(ObjAcquireThreadLock, true);

		if (NULL == (listEntry = RtlInterlockedPopEntrySList(&ObjCallWithTimeoutThreadListHead)))
		{
			if (WAIT_OBJECT_0 == WaitForSingleObject(ObjThreadReleaseEvent, INFINITE))
			{
				if (NULL == (listEntry = RtlInterlockedPopEntrySList(&ObjCallWithTimeoutThreadListHead)))
					return NULL;
			}
			else
				return NULL;
		}
	}

	return CONTAINING_RECORD(listEntry, OBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT, ListEntry);
}

static void ObjReleaseCallWithTimeoutThread(POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT ThreadContext)
{
	RtlInterlockedPushEntrySList(&ObjCallWithTimeoutThreadListHead, &ThreadContext->ListEntry);
	SetEvent(ObjThreadReleaseEvent);
}

static DWORD WINAPI workThread(LPVOID lparam)
{
	POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT threadContext = (POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT)lparam;

	// Add into internal thread.
	LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
	blpp_internalThreadSet.insert(GetCurrentThreadId());
	LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);

	threadContext->Fiber = ConvertThreadToFiber(NULL);
	SetEvent(threadContext->CompletedEventHandle);

	while (true)
	{
		if (WaitForSingleObject(threadContext->StartEventHandle, INFINITE) != WAIT_OBJECT_0)
			continue;

		if (threadContext->Routine)
			threadContext->Routine(threadContext->Context);

		SetEvent(threadContext->CompletedEventHandle);
	}

	return 0;
}

static NTSTATUS ObjCallWithTimeout(
	POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT ThreadContext,
	PUSER_ROUTINE Routine,
	PVOID Context,
	DWORD Timeout)
{
	// Create objects if necessary.

	if (NULL == ThreadContext->StartEventHandle)
	{
		ThreadContext->StartEventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);
		if (NULL == ThreadContext->StartEventHandle)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (NULL == ThreadContext->CompletedEventHandle)
	{
		ThreadContext->CompletedEventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);
		if (NULL == ThreadContext->CompletedEventHandle)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Create a query thread if we don't have one.
	if (NULL == ThreadContext->ThreadHandle)
	{
		ResetEvent(ThreadContext->StartEventHandle);
		ResetEvent(ThreadContext->CompletedEventHandle);

		ThreadContext->ThreadHandle = CreateThread(NULL, 0, workThread, ThreadContext, 0, &ThreadContext->ThreadId);
		if (NULL == ThreadContext->ThreadHandle)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// Wait for the thread to initialize.
		WaitForSingleObject(ThreadContext->CompletedEventHandle, INFINITE);
	}

	ThreadContext->Routine = Routine;
	ThreadContext->Context = Context;

	SetEvent(ThreadContext->StartEventHandle);
	DWORD waitResult = WaitForSingleObject(ThreadContext->CompletedEventHandle, Timeout);

	ThreadContext->Routine = NULL;
	MemoryBarrier();
	ThreadContext->Context = NULL;

	if (waitResult != WAIT_OBJECT_0)
	{
		// The operation timed out, or there was an error. Kill the thread.
		// On Vista and above, the thread stack is freed automatically.
		if (!TerminateThread(ThreadContext->ThreadHandle, ~0u))
		{
			TerminateThread(ThreadContext->ThreadHandle, ~0u);
		}
		WaitForSingleObject(ThreadContext->ThreadHandle, Timeout);
		CloseHandle(ThreadContext->ThreadHandle);
		ThreadContext->ThreadHandle = NULL;
		if (ThreadContext->Fiber != NULL)
		{
			DeleteFiber(ThreadContext->Fiber);
			ThreadContext->Fiber = NULL;
		}
		// Clean the internal thread.
		LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
		blpp_internalThreadSet.erase(ThreadContext->ThreadId);
		LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
		ThreadContext->ThreadId = 0;

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS ObjCallWithTimeout(
	PUSER_ROUTINE Routine,
	PVOID Context,
	DWORD CallTimeout)
{
	NTSTATUS status;
	POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT threadContext;

	if (threadContext = ObjAcquireCallWithTimeoutThread())
	{
		status = ObjCallWithTimeout(threadContext, Routine, Context, CallTimeout);
		ObjReleaseCallWithTimeoutThread(threadContext);
	}
	else
	{
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

static void ObjCommonQueryObjectRoutine(LPVOID lparam)
{
	POBJ_QUERY_OBJECT_COMMON_CONTEXT context = (POBJ_QUERY_OBJECT_COMMON_CONTEXT)lparam;

	switch (context->Work)
	{
	case NtQueryObjectWork:
		context->Status = NtQueryObject(
			context->u.NtQueryObject.Handle,
			context->u.NtQueryObject.ObjectInformationClass,
			context->u.NtQueryObject.ObjectInformation,
			context->u.NtQueryObject.ObjectInformationLength,
			context->u.NtQueryObject.ReturnLength
			);
		break;
	case NtQuerySecurityObjectWork:
		context->Status = NtQuerySecurityObject(
			context->u.NtQuerySecurityObject.Handle,
			context->u.NtQuerySecurityObject.SecurityInformation,
			context->u.NtQuerySecurityObject.SecurityDescriptor,
			context->u.NtQuerySecurityObject.Length,
			context->u.NtQuerySecurityObject.LengthNeeded
			);
		break;
	case NtSetSecurityObjectWork:
		context->Status = NtSetSecurityObject(
			context->u.NtSetSecurityObject.Handle,
			context->u.NtSetSecurityObject.SecurityInformation,
			context->u.NtSetSecurityObject.SecurityDescriptor
			);
		break;
	default:
		context->Status = STATUS_INVALID_PARAMETER;
		break;
	}
}

static NTSTATUS ObjCommonQueryObjectWithTimeout(POBJ_QUERY_OBJECT_COMMON_CONTEXT Context)
{
	NTSTATUS status = ObjCallWithTimeout(ObjCommonQueryObjectRoutine, Context, 1000);

	if (NT_SUCCESS(status))
		status = Context->Status;

	blpp_mem_free(Context);

	return status;
}

static NTSTATUS ObjCallNtQueryObjectWithTimeout(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength)
{
	POBJ_QUERY_OBJECT_COMMON_CONTEXT context;

	context = (POBJ_QUERY_OBJECT_COMMON_CONTEXT)blpp_mem_alloc(sizeof(OBJ_QUERY_OBJECT_COMMON_CONTEXT));
	context->Work = NtQueryObjectWork;
	context->Status = STATUS_UNSUCCESSFUL;
	context->u.NtQueryObject.Handle = Handle;
	context->u.NtQueryObject.ObjectInformationClass = ObjectInformationClass;
	context->u.NtQueryObject.ObjectInformation = ObjectInformation;
	context->u.NtQueryObject.ObjectInformationLength = ObjectInformationLength;
	context->u.NtQueryObject.ReturnLength = ReturnLength;

	return ObjCommonQueryObjectWithTimeout(context);
}

static NTSTATUS ObjCallNtQuerySecurityObjectWithTimeout(
	HANDLE Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG Length,
	PULONG LengthNeeded)
{
	POBJ_QUERY_OBJECT_COMMON_CONTEXT context;

	context = (POBJ_QUERY_OBJECT_COMMON_CONTEXT)blpp_mem_alloc(sizeof(OBJ_QUERY_OBJECT_COMMON_CONTEXT));
	context->Work = NtQuerySecurityObjectWork;
	context->Status = STATUS_UNSUCCESSFUL;
	context->u.NtQuerySecurityObject.Handle = Handle;
	context->u.NtQuerySecurityObject.SecurityInformation = SecurityInformation;
	context->u.NtQuerySecurityObject.SecurityDescriptor = SecurityDescriptor;
	context->u.NtQuerySecurityObject.Length = Length;
	context->u.NtQuerySecurityObject.LengthNeeded = LengthNeeded;

	return ObjCommonQueryObjectWithTimeout(context);
}

static NTSTATUS ObjCallNtSetSecurityObjectWithTimeout(
	HANDLE Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor)
{
	POBJ_QUERY_OBJECT_COMMON_CONTEXT context;

	context = (POBJ_QUERY_OBJECT_COMMON_CONTEXT)blpp_mem_alloc(sizeof(OBJ_QUERY_OBJECT_COMMON_CONTEXT));
	context->Work = NtSetSecurityObjectWork;
	context->Status = STATUS_UNSUCCESSFUL;
	context->u.NtSetSecurityObject.Handle = Handle;
	context->u.NtSetSecurityObject.SecurityInformation = SecurityInformation;
	context->u.NtSetSecurityObject.SecurityDescriptor = SecurityDescriptor;

	return ObjCommonQueryObjectWithTimeout(context);
}

static NTSTATUS ObjpGetObjectName
(
    __in HANDLE Handle,
	__in BOOLEAN WithTimeout,
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
		if (WithTimeout)
		{
			status = ObjCallNtQueryObjectWithTimeout(Handle, ObjectNameInformation, buffer, needSize, &needSize);
		}
		else
		{
			status = NtQueryObject(Handle, ObjectNameInformation, buffer, needSize, &needSize);
		}
        if (STATUS_BUFFER_OVERFLOW==status || STATUS_INFO_LENGTH_MISMATCH==status || STATUS_BUFFER_TOO_SMALL==status)
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
		ObjectName = wstring(buffer->Name.Buffer, buffer->Name.Length / sizeof(WCHAR));
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
		for (size_t i = 0; i<len; ++i)
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
		for (size_t i = 0; i<len; ++i)
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
    static PT_void inited = NULL;
    if (blpp_initOnce(&inited))
    {
        HANDLE Token;
        PTOKEN_USER tokenUser;
        WCHAR stringSid[MAX_PATH] = {0};
        Token = ObjpGetToken();
        if (Token != NULL)
        {
            if (NT_SUCCESS(ObjpQueryTokenVariableSize(Token,TokenUser,(PVOID *)&tokenUser)))
            {
                ObjSidToStringSid(tokenUser->User.Sid,stringSid,MAX_PATH*sizeof(WCHAR));
                blpp_mem_free(tokenUser);
            }
            NtClose(Token);
        }
        if (stringSid[0] != 0)
        {
            const static PWSTR registryUserPrefix = L"\\Registry\\User\\";
            const static PWSTR classesString = L"_Classes";
            hkcuPrefix = registryUserPrefix;
            hkcuPrefix.append(stringSid);
            hkcucrPrefix = hkcuPrefix;
            hkcucrPrefix.append(classesString);
        }
        else
        {
            hkcuPrefix = L"...";
            hkcucrPrefix = L"...";
        }
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

static string trim(const string& str)
{
	int first = 0;
	int last = int(str.size()) - 1;

	while (first <= last && isspace(str[first])) ++first;
	while (last >= first && isspace(str[last])) --last;

	return string(str, first, last - first + 1);
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
			serviceKeyName.append(trim(partName));
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
				if (blpp_TextEncode_AnsiToUnicode(trim(DevName).c_str(), &pwstr))
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

static void internalInitPrefix()
{
	static PT_void inited = NULL;
	if (blpp_initOnce(&inited))
	{
		ObjUpdateDosDevicePrefixes();
		ObjUpdateMupDevicePrefixes();
	}
}

bool ObjResolveDevicePrefix
(
    __inout wstring &Name
)
{
	internalInitPrefix();
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
	internalInitPrefix();
    static WCHAR WindowsPath[MAX_PATH];
    static PT_void inited = NULL;
    if (blpp_initOnce(&inited))
    {
        DWORD WinPathLength = 0;
        WinPathLength = GetWindowsDirectoryW(WindowsPath,MAX_PATH);
        if (0==WinPathLength || WinPathLength>=MAX_PATH)
        {
            return false;
        }
        WindowsPath[WinPathLength] = 0;
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
    static PT_void inited = NULL;
    static DWORD ProcessQueryAccess = PROCESS_QUERY_INFORMATION;
    static DWORD ThreadQueryAccess = THREAD_QUERY_INFORMATION;
    if (blpp_initOnce(&inited))
    {
        if (blpp_System_IsOsAtLeast(WIN_VISTA))
        {
            ProcessQueryAccess = PROCESS_QUERY_LIMITED_INFORMATION;
            ThreadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
        }
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
    OBJ_OBJECT_TYPE TypeEnum = OBJ_TYPE_Unknown;
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
    status = ObjpGetObjectTypeName(Handle,TypeName,TypeEnum);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (ObjType)
    {
        *ObjType = TypeEnum;
    }
    if (OBJ_TYPE_File == TypeEnum)
    {
#define QUERY_NORMALLY 0
#define QUERY_WITH_TIMEOUT 1
#define QUERY_FAIL 2

		ULONG hackLevel = QUERY_WITH_TIMEOUT;

		// We can't use the timeout method on XP because hanging threads can't even be terminated!
		// But I'd like to try.
/*
		if (WindowsVersion <= WINDOWS_XP)
			hackLevel = QUERY_FAIL;
*/

		if (hackLevel == QUERY_NORMALLY || hackLevel == QUERY_WITH_TIMEOUT)
		{
			status = ObjpGetObjectName(Handle, hackLevel == QUERY_WITH_TIMEOUT, BestObjectName);
		}
		else
		{
			// Pretend the file object has no name.
			BestObjectName.clear();
			status = STATUS_SUCCESS;
		}
    }
    else
    {
        // Query the object normally.
        status = ObjpGetObjectName(Handle,FALSE,BestObjectName);
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

void ObjUninit()
{
	if (ObjCallWithTimeoutThreadInited)
	{
		// Free all threads.
		PSLIST_ENTRY listEntry;
		while (listEntry = RtlInterlockedPopEntrySList(&ObjCallWithTimeoutThreadListHead))
		{
			POBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT ThreadContext = CONTAINING_RECORD(listEntry, OBJ_CALL_WITH_TIMEOUT_THREAD_CONTEXT, ListEntry);
			if (!TerminateThread(ThreadContext->ThreadHandle, ~0u))
			{
				TerminateThread(ThreadContext->ThreadHandle, ~0u);
			}
			WaitForSingleObject(ThreadContext->ThreadHandle, 1000);
			CloseHandle(ThreadContext->ThreadHandle);
			ThreadContext->ThreadHandle = NULL;
			if (ThreadContext->Fiber != NULL)
			{
				DeleteFiber(ThreadContext->Fiber);
				ThreadContext->Fiber = NULL;
			}
			// Clean the internal thread.
			LOCK_AcquireQueuedLockExclusive(&blpp_internalThreadSetLock);
			blpp_internalThreadSet.erase(ThreadContext->ThreadId);
			LOCK_ReleaseQueuedLockExclusive(&blpp_internalThreadSetLock);
			ThreadContext->ThreadId = 0;
			CloseHandle(ThreadContext->StartEventHandle);
			ThreadContext->StartEventHandle = NULL;
			CloseHandle(ThreadContext->CompletedEventHandle);
			ThreadContext->CompletedEventHandle = NULL;
			blpp_mem_free(ThreadContext);
		}
	}
}
