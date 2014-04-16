
#pragma once

typedef enum _OBJ_OBJECT_TYPE
{
    OBJ_TYPE_Unknown = 0,
    OBJ_TYPE_Adapter,
    OBJ_TYPE_ALPC_Port,
    OBJ_TYPE_Callback,
    OBJ_TYPE_Controller,
    OBJ_TYPE_DebugObject,
    OBJ_TYPE_Desktop,
    OBJ_TYPE_Device,
    OBJ_TYPE_Directory,
    OBJ_TYPE_Driver,
    OBJ_TYPE_EtwConsumer,
    OBJ_TYPE_EtwRegistration,
    OBJ_TYPE_Event,
    OBJ_TYPE_EventPair,
    OBJ_TYPE_File,
    OBJ_TYPE_FilterCommunicationPort,
    OBJ_TYPE_FilterConnectionPort,
    OBJ_TYPE_IoCompletion,
    OBJ_TYPE_IoCompletionReserve,
    OBJ_TYPE_Job,
    OBJ_TYPE_Key,
    OBJ_TYPE_KeyedEvent,
    OBJ_TYPE_Mutant,
    OBJ_TYPE_PcwObject,
    OBJ_TYPE_PowerRequest,
    OBJ_TYPE_Process,
    OBJ_TYPE_Profile,
    OBJ_TYPE_Section,
    OBJ_TYPE_Semaphore,
    OBJ_TYPE_Session,
    OBJ_TYPE_SymbolicLink,
    OBJ_TYPE_Thread,
    OBJ_TYPE_Timer,
    OBJ_TYPE_TmEn,
    OBJ_TYPE_TmRm,
    OBJ_TYPE_TmTm,
    OBJ_TYPE_TmTx,
    OBJ_TYPE_Token,
    OBJ_TYPE_TpWorkerFactory,
    OBJ_TYPE_Type,
    OBJ_TYPE_UserApcReserve,
    OBJ_TYPE_WindowStation,
    OBJ_TYPE_WmiGuid,
    OBJ_TYPE_ALL_COUNT
} OBJ_OBJECT_TYPE;

#include "../basic_fun.h"
#include "../my_krnlDef/krnlDef.h"

#include <xstring>
using namespace std;

void ObjUpdateDosDevicePrefixes();
void ObjUpdateMupDevicePrefixes();

bool ObjResolveDevicePrefix(__inout wstring &Name);
bool ObjGetFileName(__inout wstring &Name);

bool ObjFormatNativeKeyName(__inout wstring &Name);

NTSTATUS ObjGetHandleInformation
(
    __in HANDLE Handle,
    __out_opt POBJECT_BASIC_INFORMATION BasicInformation,
    __out_opt OBJ_OBJECT_TYPE *ObjType,
    __out wstring &TypeName,
    __out wstring &BestObjectName,
    __out_opt PCLIENT_ID BestId
);

void ObjInit();
void ObjUninit();
