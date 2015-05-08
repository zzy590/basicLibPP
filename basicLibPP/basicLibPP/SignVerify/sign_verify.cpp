//////////////////////////////////////////////////////////////////////////
//
// Verify
//
// Author: ZZY
//
//////////////////////////////////////////////////////////////////////////


#include "../basic_fun.h"
#include "sign_verify.h"

#include <WinTrust.h>
#include <SoftPub.h>
#include <mscat.h>
#include <Guiddef.h>


//////////////////////////////////////////////////////////////////////////


typedef BOOL (WINAPI *_CryptCATAdminCalcHashFromFileHandle)(
	HANDLE hFile,
	DWORD *pcbHash,
	BYTE *pbHash,
	DWORD dwFlags
	);

typedef BOOL (WINAPI *_CryptCATAdminCalcHashFromFileHandle2)(
	HCATADMIN hCatAdmin,
	HANDLE hFile,
	DWORD *pcbHash,
	BYTE *pbHash,
	DWORD dwFlags
	);

typedef BOOL (WINAPI *_CryptCATAdminAcquireContext)(
	HANDLE *phCatAdmin,
	GUID *pgSubsystem,
	DWORD dwFlags
	);

#ifndef _WIN64
typedef LPCVOID PCCERT_STRONG_SIGN_PARA;
#endif

typedef BOOL (WINAPI *_CryptCATAdminAcquireContext2)(
	HCATADMIN *phCatAdmin,
	const GUID *pgSubsystem,
	PCWSTR pwszHashAlgorithm,
	PCCERT_STRONG_SIGN_PARA pStrongHashPolicy,
	DWORD dwFlags
	);

typedef HANDLE (WINAPI *_CryptCATAdminEnumCatalogFromHash)(
	HANDLE hCatAdmin,
	BYTE *pbHash,
	DWORD cbHash,
	DWORD dwFlags,
	HANDLE *phPrevCatInfo
	);

typedef BOOL (WINAPI *_CryptCATCatalogInfoFromContext)(
	HANDLE hCatInfo,
	CATALOG_INFO *psCatInfo,
	DWORD dwFlags
	);

typedef BOOL (WINAPI *_CryptCATAdminReleaseCatalogContext)(
	HANDLE hCatAdmin,
	HANDLE hCatInfo,
	DWORD dwFlags
	);

typedef BOOL (WINAPI *_CryptCATAdminReleaseContext)(
	HANDLE hCatAdmin,
	DWORD dwFlags
	);

typedef PCRYPT_PROVIDER_DATA (WINAPI *_WTHelperProvDataFromStateData)(
	HANDLE hStateData
	);

typedef PCRYPT_PROVIDER_SGNR (WINAPI *_WTHelperGetProvSignerFromChain)(
	CRYPT_PROVIDER_DATA *pProvData,
	DWORD idxSigner,
	BOOL fCounterSigner,
	DWORD idxCounterSigner
	);

typedef LONG (WINAPI *_WinVerifyTrust)(
	HWND hWnd,
	GUID *pgActionID,
	LPVOID pWVTData
	);

typedef DWORD (WINAPI *_CertNameToStr)(
	DWORD dwCertEncodingType,
	PCERT_NAME_BLOB pName,
	DWORD dwStrType,
	LPTSTR psz,
	DWORD csz
	);

typedef PCCERT_CONTEXT (WINAPI *_CertDuplicateCertificateContext)(
	_In_ PCCERT_CONTEXT pCertContext
	);

typedef BOOL (WINAPI *_CertFreeCertificateContext)(
	_In_ PCCERT_CONTEXT pCertContext
	);

typedef struct tagCRYPTUI_VIEWSIGNERINFO_STRUCT {
	DWORD dwSize;
	HWND hwndParent;
	DWORD dwFlags;
	LPCTSTR szTitle;
	CMSG_SIGNER_INFO *pSignerInfo;
	HCRYPTMSG hMsg;
	LPCSTR pszOID;
	DWORD_PTR dwReserved;
	DWORD cStores;
	HCERTSTORE *rghStores;
	DWORD cPropSheetPages;
	LPCPROPSHEETPAGE rgPropSheetPages;
} CRYPTUI_VIEWSIGNERINFO_STRUCT, *PCRYPTUI_VIEWSIGNERINFO_STRUCT;

typedef BOOL (WINAPI *_CryptUIDlgViewSignerInfo)(
	_In_ CRYPTUI_VIEWSIGNERINFO_STRUCT *pcvsi
	);

static _CryptCATAdminCalcHashFromFileHandle pfn_CryptCATAdminCalcHashFromFileHandle;
static _CryptCATAdminCalcHashFromFileHandle2 pfn_CryptCATAdminCalcHashFromFileHandle2;
static _CryptCATAdminAcquireContext pfn_CryptCATAdminAcquireContext;
static _CryptCATAdminAcquireContext2 pfn_CryptCATAdminAcquireContext2;
static _CryptCATAdminEnumCatalogFromHash pfn_CryptCATAdminEnumCatalogFromHash;
static _CryptCATCatalogInfoFromContext pfn_CryptCATCatalogInfoFromContext;
static _CryptCATAdminReleaseCatalogContext pfn_CryptCATAdminReleaseCatalogContext;
static _CryptCATAdminReleaseContext pfn_CryptCATAdminReleaseContext;
static _WTHelperProvDataFromStateData pfn_WTHelperProvDataFromStateData;
static _WTHelperGetProvSignerFromChain pfn_WTHelperGetProvSignerFromChain;
static _WinVerifyTrust pfn_WinVerifyTrust;
static _CertNameToStr pfn_CertNameToStr;
static _CertDuplicateCertificateContext pfn_CertDuplicateCertificateContext;
static _CertFreeCertificateContext pfn_CertFreeCertificateContext;
static _CryptUIDlgViewSignerInfo pfn_CryptUIDlgViewSignerInfo;

static GUID WinTrustActionGenericVerifyV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static GUID DriverActionVerify = DRIVER_ACTION_VERIFY;

static BOOL VerifyInitOnce = FALSE;

static VOID PhpVerifyInitialization()
{
	HMODULE wt = LoadLibraryA("wintrust.dll");
	HMODULE cr = LoadLibraryA("crypt32.dll");
	HMODULE cu = LoadLibraryA("cryptui.dll");

	pfn_CryptCATAdminCalcHashFromFileHandle =
		(_CryptCATAdminCalcHashFromFileHandle)GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle");
	pfn_CryptCATAdminCalcHashFromFileHandle2 =
		(_CryptCATAdminCalcHashFromFileHandle2)GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2");
	pfn_CryptCATAdminAcquireContext =
		(_CryptCATAdminAcquireContext)GetProcAddress(wt, "CryptCATAdminAcquireContext");
	pfn_CryptCATAdminAcquireContext2 =
		(_CryptCATAdminAcquireContext2)GetProcAddress(wt, "CryptCATAdminAcquireContext2");
	pfn_CryptCATAdminEnumCatalogFromHash =
		(_CryptCATAdminEnumCatalogFromHash)GetProcAddress(wt, "CryptCATAdminEnumCatalogFromHash");
	pfn_CryptCATCatalogInfoFromContext =
		(_CryptCATCatalogInfoFromContext)GetProcAddress(wt, "CryptCATCatalogInfoFromContext");
	pfn_CryptCATAdminReleaseCatalogContext =
		(_CryptCATAdminReleaseCatalogContext)GetProcAddress(wt, "CryptCATAdminReleaseCatalogContext");
	pfn_CryptCATAdminReleaseContext =
		(_CryptCATAdminReleaseContext)GetProcAddress(wt, "CryptCATAdminReleaseContext");
	pfn_WTHelperProvDataFromStateData =
		(_WTHelperProvDataFromStateData)GetProcAddress(wt, "WTHelperProvDataFromStateData");
	pfn_WTHelperGetProvSignerFromChain =
		(_WTHelperGetProvSignerFromChain)GetProcAddress(wt, "WTHelperGetProvSignerFromChain");
	pfn_WinVerifyTrust =
		(_WinVerifyTrust)GetProcAddress(wt, "WinVerifyTrust");
	pfn_CertNameToStr =
		(_CertNameToStr)GetProcAddress(cr, "CertNameToStrW");
	pfn_CertDuplicateCertificateContext =
		(_CertDuplicateCertificateContext)GetProcAddress(cr, "CertDuplicateCertificateContext");
	pfn_CertFreeCertificateContext =
		(_CertFreeCertificateContext)GetProcAddress(cr, "CertFreeCertificateContext");
	pfn_CryptUIDlgViewSignerInfo =
		(_CryptUIDlgViewSignerInfo)GetProcAddress(cu, "CryptUIDlgViewSignerInfo");
}

static BLPP_VERIFY_RESULT PhpStatusToVerifyResult(LONG Status)
{
	switch (Status)
	{
	case 0:
		return VrTrusted;
	case TRUST_E_NOSIGNATURE:
		return VrNoSignature;
	case CERT_E_EXPIRED:
		return VrExpired;
	case CERT_E_REVOKED:
		return VrRevoked;
	case TRUST_E_EXPLICIT_DISTRUST:
		return VrDistrust;
	case CRYPT_E_SECURITY_SETTINGS:
		return VrSecuritySettings;
	case TRUST_E_BAD_DIGEST:
		return VrBadSignature;
	default:
		return VrSecuritySettings;
	}
}

BOOLEAN PhpGetSignaturesFromStateData(
    _In_ HANDLE StateData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    PCRYPT_PROVIDER_DATA provData;
    PCRYPT_PROVIDER_SGNR sgnr;
    PCERT_CONTEXT *signatures;
    ULONG i;
    ULONG numberOfSignatures;
    ULONG index;

    provData = pfn_WTHelperProvDataFromStateData(StateData);

    if (!provData)
    {
        *Signatures = NULL;
        *NumberOfSignatures = 0;
        return FALSE;
    }

    i = 0;
    numberOfSignatures = 0;

    while (sgnr = pfn_WTHelperGetProvSignerFromChain(provData, i, FALSE, 0))
    {
        if (sgnr->csCertChain != 0)
            numberOfSignatures++;

        i++;
    }

    if (numberOfSignatures != 0)
    {
        signatures = (PCERT_CONTEXT *)blpp_mem_alloc(numberOfSignatures * sizeof(PCERT_CONTEXT));
        i = 0;
        index = 0;

        while (sgnr = pfn_WTHelperGetProvSignerFromChain(provData, i, FALSE, 0))
        {
            if (sgnr->csCertChain != 0)
                signatures[index++] = (PCERT_CONTEXT)pfn_CertDuplicateCertificateContext(sgnr->pasCertChain[0].pCert);

            i++;
        }
    }
    else
    {
        signatures = NULL;
    }

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return TRUE;
}

VOID PhpViewSignerInfo(
    _In_ PBLPP_VERIFY_FILE_INFO Information,
    _In_ HANDLE StateData
    )
{
    if (pfn_CryptUIDlgViewSignerInfo)
    {
        CRYPTUI_VIEWSIGNERINFO_STRUCT viewSignerInfo = { sizeof(CRYPTUI_VIEWSIGNERINFO_STRUCT) };
        PCRYPT_PROVIDER_DATA provData;
        PCRYPT_PROVIDER_SGNR sgnr;

        if (!(provData = pfn_WTHelperProvDataFromStateData(StateData)))
            return;
        if (!(sgnr = pfn_WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0)))
            return;

        viewSignerInfo.hwndParent = Information->hWnd;
        viewSignerInfo.pSignerInfo = sgnr->psSigner;
        viewSignerInfo.hMsg = provData->hMsg;
        viewSignerInfo.pszOID = szOID_PKIX_KP_CODE_SIGNING;
        pfn_CryptUIDlgViewSignerInfo(&viewSignerInfo);
    }
}

BLPP_VERIFY_RESULT PhpVerifyFile(
    _In_ PBLPP_VERIFY_FILE_INFO Information,
    _In_ HANDLE FileHandle,
    _In_ ULONG UnionChoice,
    _In_ PVOID UnionData,
    _In_ LPGUID ActionId,
    _In_opt_ PVOID PolicyCallbackData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    LONG status;
    WINTRUST_DATA trustData = { 0 };

    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = PolicyCallbackData;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = UnionChoice;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    trustData.pFile = (PWINTRUST_FILE_INFO)UnionData;

    if (UnionChoice == WTD_CHOICE_CATALOG)
        trustData.pCatalog = (PWINTRUST_CATALOG_INFO)UnionData;

    if (Information->Flags & BLPP_VERIFY_PREVENT_NETWORK_ACCESS)
    {
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;

        if (blpp_System_IsOsAtLeast(WIN_VISTA))
            trustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
        else
            trustData.dwProvFlags |= WTD_REVOCATION_CHECK_NONE;
    }

    status = pfn_WinVerifyTrust(NULL, ActionId, &trustData);
    PhpGetSignaturesFromStateData(trustData.hWVTStateData, Signatures, NumberOfSignatures);

    if (status == 0 && (Information->Flags & BLPP_VERIFY_VIEW_PROPERTIES))
        PhpViewSignerInfo(Information, trustData.hWVTStateData);

    // Close the state data.
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    pfn_WinVerifyTrust(NULL, ActionId, &trustData);

    return PhpStatusToVerifyResult(status);
}

BOOLEAN PhpCalculateFileHash(
    _In_ HANDLE FileHandle,
    _In_ PWSTR HashAlgorithm,
    _Out_ PUCHAR *FileHash,
    _Out_ PULONG FileHashLength,
    _Out_ HANDLE *CatAdminHandle
    )
{
    HANDLE catAdminHandle;
    PUCHAR fileHash;
    ULONG fileHashLength;

    if (pfn_CryptCATAdminAcquireContext2)
    {
        if (!pfn_CryptCATAdminAcquireContext2(&catAdminHandle, &DriverActionVerify, HashAlgorithm, NULL, 0))
            return FALSE;
    }
    else
    {
        if (!pfn_CryptCATAdminAcquireContext(&catAdminHandle, &DriverActionVerify, 0))
            return FALSE;
    }

    fileHashLength = 32;
    fileHash = (PUCHAR)blpp_mem_alloc(fileHashLength);

    if (pfn_CryptCATAdminCalcHashFromFileHandle2)
    {
        if (!pfn_CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
        {
            blpp_mem_free(fileHash);
            fileHash = (PUCHAR)blpp_mem_alloc(fileHashLength);

            if (!pfn_CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
            {
                pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
                blpp_mem_free(fileHash);
                return FALSE;
            }
        }
    }
    else
    {
        if (!pfn_CryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
        {
            blpp_mem_free(fileHash);
            fileHash = (PUCHAR)blpp_mem_alloc(fileHashLength);

            if (!pfn_CryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
            {
                pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
                blpp_mem_free(fileHash);
                return FALSE;
            }
        }
    }

    *FileHash = fileHash;
    *FileHashLength = fileHashLength;
    *CatAdminHandle = catAdminHandle;

    return TRUE;
}

VOID PhFreeVerifySignatures(
	_In_ PCERT_CONTEXT *Signatures,
	_In_ ULONG NumberOfSignatures
	)
{
	ULONG i;

	if (Signatures)
	{
		for (i = 0; i < NumberOfSignatures; i++)
			pfn_CertFreeCertificateContext(Signatures[i]);

		blpp_mem_free(Signatures);
	}
}

static PCT_wstr bufferToHexString(PCT_void data,size_t length)
{
	const static char decoder[] = "0123456789ABCDEF";
	PT_wstr str = (PT_wstr)blpp_mem_alloc((length*2+1)*sizeof(WCHAR));
	if (NULL == str)
	{
		return NULL;
	}
	PCT_byte ptr = (PCT_byte)data;
	for (size_t i=0;i<length;++i)
	{
		str[i*2] = decoder[ptr[i]>>4];
		str[i*2+1] = decoder[ptr[i]&0xf];
	}
	str[length*2] = 0;
	return str;
}

typedef struct MY_WINTRUST_CATALOG_INFO_ {
	DWORD                                 cbStruct;
	DWORD                                 dwCatalogVersion;
	LPCWSTR                               pcwszCatalogFilePath;
	LPCWSTR                               pcwszMemberTag;
	LPCWSTR                               pcwszMemberFilePath;
	HANDLE                                hMemberFile;
	BYTE                                 *pbCalculatedFileHash;
	DWORD                                 cbCalculatedFileHash;
	PCCTL_CONTEXT                         pcCatalogContext;
	HCATADMIN                             hCatAdmin;
} MY_WINTRUST_CATALOG_INFO, *PMY_WINTRUST_CATALOG_INFO;

BLPP_VERIFY_RESULT PhpVerifyFileFromCatalog(
    _In_ PBLPP_VERIFY_FILE_INFO Information,
    _In_ HANDLE FileHandle,
    _In_opt_ PWSTR HashAlgorithm,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    BLPP_VERIFY_RESULT verifyResult = VrNoSignature;
    PCERT_CONTEXT *signatures;
    ULONG numberOfSignatures;
    MY_WINTRUST_CATALOG_INFO catalogInfo = { 0 };
    LARGE_INTEGER fileSize;
    ULONG fileSizeLimit;
    PUCHAR fileHash;
    ULONG fileHashLength;
    PCT_wstr fileHashTag;
    HANDLE catAdminHandle;
    HANDLE catInfoHandle;
    ULONG i;

    *Signatures = NULL;
    *NumberOfSignatures = 0;

    if (!GetFileSizeEx(FileHandle,&fileSize))
        return VrNoSignature;

    signatures = NULL;
    numberOfSignatures = 0;

    if (Information->FileSizeLimitForHash != -1)
    {
        fileSizeLimit = BLPP_VERIFY_DEFAULT_SIZE_LIMIT;

        if (Information->FileSizeLimitForHash != 0)
            fileSizeLimit = Information->FileSizeLimitForHash;

        if (fileSize.QuadPart > fileSizeLimit)
            return VrNoSignature;
    }

    if (PhpCalculateFileHash(FileHandle, HashAlgorithm, &fileHash, &fileHashLength, &catAdminHandle))
    {
        fileHashTag = bufferToHexString(fileHash, fileHashLength);

        // Search the system catalogs.

        catInfoHandle = pfn_CryptCATAdminEnumCatalogFromHash(
            catAdminHandle,
            fileHash,
            fileHashLength,
            0,
            NULL
            );

        if (catInfoHandle)
        {
            CATALOG_INFO ci = { 0 };
            DRIVER_VER_INFO verInfo = { 0 };

            if (pfn_CryptCATCatalogInfoFromContext(catInfoHandle, &ci, 0))
            {
                // Disable OS version checking by passing in a DRIVER_VER_INFO structure.
                verInfo.cbStruct = sizeof(DRIVER_VER_INFO);

                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = ci.wszCatalogFile;
                catalogInfo.pcwszMemberFilePath = Information->FileName;
                catalogInfo.pcwszMemberTag = fileHashTag;
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                catalogInfo.hCatAdmin = catAdminHandle;
                verifyResult = PhpVerifyFile(Information, FileHandle, WTD_CHOICE_CATALOG, &catalogInfo, &DriverActionVerify, &verInfo, &signatures, &numberOfSignatures);

                if (verInfo.pcSignerCertContext)
                    pfn_CertFreeCertificateContext(verInfo.pcSignerCertContext);
            }

            pfn_CryptCATAdminReleaseCatalogContext(catAdminHandle, catInfoHandle, 0);
        }
        else
        {
            // Search any user-supplied catalogs.

            for (i = 0; i < Information->NumberOfCatalogFileNames; i++)
            {
                PhFreeVerifySignatures(signatures, numberOfSignatures);

                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = Information->CatalogFileNames[i];
                catalogInfo.pcwszMemberFilePath = Information->FileName;
                catalogInfo.pcwszMemberTag = fileHashTag;
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                catalogInfo.hCatAdmin = catAdminHandle;
                verifyResult = PhpVerifyFile(Information, FileHandle, WTD_CHOICE_CATALOG, &catalogInfo, &WinTrustActionGenericVerifyV2, NULL, &signatures, &numberOfSignatures);

                if (verifyResult == VrTrusted)
                    break;
            }
        }

        blpp_mem_free((PT_void)fileHashTag);
        blpp_mem_free(fileHash);
        pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
    }

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return verifyResult;
}

NTSTATUS PhVerifyFileEx(
    _In_ PBLPP_VERIFY_FILE_INFO Information,
    _Out_ BLPP_VERIFY_RESULT *VerifyResult,
    _Out_opt_ PCERT_CONTEXT **Signatures,
    _Out_opt_ PULONG NumberOfSignatures
    )
{
    HANDLE fileHandle;
    BLPP_VERIFY_RESULT verifyResult;
    PCERT_CONTEXT *signatures;
    ULONG numberOfSignatures;
    WINTRUST_FILE_INFO fileInfo = { 0 };

    if (FALSE == VerifyInitOnce)
    {
        PhpVerifyInitialization();
        VerifyInitOnce = TRUE;
    }

    // Make sure we have successfully imported
    // the required functions.
    if (
        !pfn_CryptCATAdminCalcHashFromFileHandle ||
        !pfn_CryptCATAdminAcquireContext ||
        !pfn_CryptCATAdminEnumCatalogFromHash ||
        !pfn_CryptCATCatalogInfoFromContext ||
        !pfn_CryptCATAdminReleaseCatalogContext ||
        !pfn_CryptCATAdminReleaseContext ||
        !pfn_WinVerifyTrust ||
        !pfn_WTHelperProvDataFromStateData ||
        !pfn_WTHelperGetProvSignerFromChain ||
        !pfn_CertNameToStr ||
        !pfn_CertDuplicateCertificateContext ||
        !pfn_CertFreeCertificateContext
        )
        return STATUS_NOT_SUPPORTED;

	fileHandle = CreateFileW(Information->FileName,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (INVALID_HANDLE_VALUE == fileHandle)
        return STATUS_ACCESS_DENIED;

    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = Information->FileName;
    fileInfo.hFile = fileHandle;

    verifyResult = PhpVerifyFile(Information, fileHandle, WTD_CHOICE_FILE, &fileInfo, &WinTrustActionGenericVerifyV2, NULL, &signatures, &numberOfSignatures);

    if (verifyResult == VrNoSignature)
    {
        if (pfn_CryptCATAdminAcquireContext2 && pfn_CryptCATAdminCalcHashFromFileHandle2)
        {
            PhFreeVerifySignatures(signatures, numberOfSignatures);
            verifyResult = PhpVerifyFileFromCatalog(Information, fileHandle, BCRYPT_SHA256_ALGORITHM, &signatures, &numberOfSignatures);
        }

        if (verifyResult != VrTrusted)
        {
            PhFreeVerifySignatures(signatures, numberOfSignatures);
            verifyResult = PhpVerifyFileFromCatalog(Information, fileHandle, NULL, &signatures, &numberOfSignatures);
        }
    }

    *VerifyResult = verifyResult;

    if (Signatures)
        *Signatures = signatures;
    else
        PhFreeVerifySignatures(signatures, numberOfSignatures);

    if (NumberOfSignatures)
        *NumberOfSignatures = numberOfSignatures;

    CloseHandle(fileHandle);

    return STATUS_SUCCESS;
}

BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignW(PCT_wstr FileName)
{
	BLPP_VERIFY_FILE_INFO info = { 0 };
	BLPP_VERIFY_RESULT verifyResult;
	PCERT_CONTEXT *signatures;
	ULONG numberOfSignatures;

	info.FileName = (PT_wstr)FileName;
	info.Flags = BLPP_VERIFY_PREVENT_NETWORK_ACCESS;

	if (NT_SUCCESS(PhVerifyFileEx(&info, &verifyResult, &signatures, &numberOfSignatures)))
	{
		PhFreeVerifySignatures(signatures, numberOfSignatures);
		return verifyResult;
	}
	else
	{
		return VrNoSignature;
	}
}

BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignA(PCT_str FileName)
{
    BLPP_VERIFY_RESULT bResult = VrUnknown;
    PT_wstr wstr;
    if (blpp_TextEncode_AnsiToUnicode(FileName,&wstr))
    {
        bResult = blpp_SignVerify_VerifyFileSignW(wstr);
        blpp_mem_free(wstr);
    }
    return bResult;
}
