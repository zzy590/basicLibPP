//////////////////////////////////////////////////////////////////////////
//
// Verify
//
// Author: ZZY
//
//////////////////////////////////////////////////////////////////////////


#include "../basic_fun.h"

#include <WinTrust.h>
#include <SoftPub.h>
#include <mscat.h>


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

typedef LPCVOID PCCERT_STRONG_SIGN_PARA;

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

_CryptCATAdminCalcHashFromFileHandle pfn_CryptCATAdminCalcHashFromFileHandle;
_CryptCATAdminCalcHashFromFileHandle2 pfn_CryptCATAdminCalcHashFromFileHandle2;
_CryptCATAdminAcquireContext pfn_CryptCATAdminAcquireContext;
_CryptCATAdminAcquireContext2 pfn_CryptCATAdminAcquireContext2;
_CryptCATAdminEnumCatalogFromHash pfn_CryptCATAdminEnumCatalogFromHash;
_CryptCATCatalogInfoFromContext pfn_CryptCATCatalogInfoFromContext;
_CryptCATAdminReleaseCatalogContext pfn_CryptCATAdminReleaseCatalogContext;
_CryptCATAdminReleaseContext pfn_CryptCATAdminReleaseContext;
_WTHelperProvDataFromStateData pfn_WTHelperProvDataFromStateData;
_WTHelperGetProvSignerFromChain pfn_WTHelperGetProvSignerFromChain;
_WinVerifyTrust pfn_WinVerifyTrust;
_CertNameToStr pfn_CertNameToStr;
_CertDuplicateCertificateContext pfn_CertDuplicateCertificateContext;
_CertFreeCertificateContext pfn_CertFreeCertificateContext;

static BOOL pVerifyInitOnce = FALSE;

static CHAR PhIntegerToCharUpper[] =
	"0123456789" /* 0 - 9 */
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 10 - 35 */
	" !\"#$%&'()*+,-./" /* 36 - 51 */
	":;<=>?@" /* 52 - 58 */
	"[\\]^_`" /* 59 - 64 */
	"{|}~" /* 65 - 68 */
	;

static VOID PhpVerifyInitialization()
{
	HMODULE wt = LoadLibraryA("wintrust.dll");
	HMODULE cr = LoadLibraryA("crypt32.dll");

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
		(CertFreeCertificateContext)GetProcAddress(cr, "CertFreeCertificateContext");
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

static BLPP_VERIFY_RESULT PhpVerifyFileBasic(PCWSTR FileName)
{
	LONG status;
	WINTRUST_DATA trustData;
	WINTRUST_FILE_INFO fileInfo;
	GUID actionGenericVerifyV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	memset(&trustData,0,sizeof(WINTRUST_DATA));
	memset(&fileInfo,0,sizeof(WINTRUST_FILE_INFO));

	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = FileName;

	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.dwProvFlags = WTD_SAFER_FLAG|WTD_REVOCATION_CHECK_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.dwStateAction = WTD_STATEACTION_IGNORE;
	trustData.pFile = &fileInfo;

	status = pfn_WinVerifyTrust(NULL, &actionGenericVerifyV2, &trustData);

	return PhpStatusToVerifyResult(status);
}

//
// New type of catalog info.
//

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

static BLPP_VERIFY_RESULT PhpVerifyFileFromCatalog(PCWSTR FileName,PWSTR HashAlgorithm)
{
	LONG status = TRUST_E_NOSIGNATURE;
	WINTRUST_DATA trustData;
	MY_WINTRUST_CATALOG_INFO catalogInfo;
	GUID driverActionVerify = DRIVER_ACTION_VERIFY;
	HANDLE fileHandle;
	LARGE_INTEGER fileSize;
	PBYTE fileHash = NULL;
	ULONG fileHashLength;
	PWSTR fileHashTag = NULL;
	HANDLE catAdminHandle = NULL;
	HANDLE catInfoHandle = NULL;
	ULONG i;

	memset(&trustData,0,sizeof(WINTRUST_DATA));
	memset(&catalogInfo,0,sizeof(MY_WINTRUST_CATALOG_INFO));

	fileHandle = CreateFileW(FileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
	if (INVALID_HANDLE_VALUE == fileHandle)
	{
		return VrNoSignature;
	}

	// Don't try to hash files over 32 MB in size.
	if (!GetFileSizeEx(fileHandle,&fileSize) || (fileSize.QuadPart > 32 * 1024 * 1024))
	{
		return VrNoSignature;
	}

	if (pfn_CryptCATAdminAcquireContext2)
	{
		if (!pfn_CryptCATAdminAcquireContext2(&catAdminHandle, &driverActionVerify, HashAlgorithm, NULL, 0))
		{
			CloseHandle(fileHandle);
			return VrNoSignature;
		}
	}
	else
	{
		if (!pfn_CryptCATAdminAcquireContext(&catAdminHandle, &driverActionVerify, 0))
		{
			CloseHandle(fileHandle);
			return VrNoSignature;
		}
	}

	fileHashLength = 256;
	fileHash = (PBYTE)blpp_mem_alloc(fileHashLength);

	if (pfn_CryptCATAdminCalcHashFromFileHandle2)
	{
		if (!pfn_CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, fileHandle, &fileHashLength, fileHash, 0))
		{
			blpp_mem_free(fileHash);
			fileHash = (PBYTE)blpp_mem_alloc(fileHashLength);

			if (!pfn_CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, fileHandle, &fileHashLength, fileHash, 0))
			{
				pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
				CloseHandle(fileHandle);
				blpp_mem_free(fileHash);
				return VrNoSignature;
			}
		}
	}
	else
	{
		if (!pfn_CryptCATAdminCalcHashFromFileHandle(fileHandle, &fileHashLength, fileHash, 0))
		{
			blpp_mem_free(fileHash);
			fileHash = (PBYTE)blpp_mem_alloc(fileHashLength);

			if (!pfn_CryptCATAdminCalcHashFromFileHandle(fileHandle, &fileHashLength, fileHash, 0))
			{
				pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
				CloseHandle(fileHandle);
				blpp_mem_free(fileHash);
				return VrNoSignature;
			}
		}
	}

	CloseHandle(fileHandle);

	fileHashTag = (PWSTR)blpp_mem_alloc((fileHashLength * 2 + 1) * sizeof(WCHAR));

	for (i = 0; i < fileHashLength; i++)
	{
		fileHashTag[i * 2] = PhIntegerToCharUpper[fileHash[i] >> 4];
		fileHashTag[i * 2 + 1] = PhIntegerToCharUpper[fileHash[i] & 0xf];
	}

	fileHashTag[fileHashLength * 2] = 0;

	catInfoHandle = pfn_CryptCATAdminEnumCatalogFromHash(
		catAdminHandle,
		fileHash,
		fileHashLength,
		0,
		NULL
		);

	blpp_mem_free(fileHash);

	if (catInfoHandle)
	{
		CATALOG_INFO ci = { 0 };

		if (pfn_CryptCATCatalogInfoFromContext(catInfoHandle, &ci, 0))
		{
			catalogInfo.cbStruct = sizeof(catalogInfo);
			catalogInfo.pcwszCatalogFilePath = ci.wszCatalogFile;
			catalogInfo.pcwszMemberFilePath = FileName;
			catalogInfo.pcwszMemberTag = fileHashTag;
			catalogInfo.hCatAdmin = catAdminHandle;

			trustData.cbStruct = sizeof(trustData);
			trustData.dwUIChoice = WTD_UI_NONE;
			trustData.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
			trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
			trustData.dwStateAction = WTD_STATEACTION_VERIFY;
			trustData.pCatalog = (PWINTRUST_CATALOG_INFO)&catalogInfo;
			trustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;				

			status = pfn_WinVerifyTrust(NULL, &driverActionVerify, &trustData);

			// Close the state data.
			trustData.dwStateAction = WTD_STATEACTION_CLOSE;
			pfn_WinVerifyTrust(NULL, &driverActionVerify, &trustData);
		}

		pfn_CryptCATAdminReleaseCatalogContext(catAdminHandle, catInfoHandle, 0);
	}

	blpp_mem_free(fileHashTag);
	pfn_CryptCATAdminReleaseContext(catAdminHandle, 0);
	return PhpStatusToVerifyResult(status);
}

BLPP_VERIFY_RESULT blpp_SignVerify_VerifyFileSignW(PCT_wstr FileName)
{
	BLPP_VERIFY_RESULT bResult;
	if (!pVerifyInitOnce)
	{
		PhpVerifyInitialization();
		pVerifyInitOnce = TRUE;
	}

	if (!pfn_WinVerifyTrust)
	{
		return VrUnknown;
	}

	bResult = PhpVerifyFileBasic(FileName);
	if (VrNoSignature != bResult)
	{
		return bResult;
	}

	// Make sure we have successfully imported
	// the required functions.
	if (
		!pfn_CryptCATAdminCalcHashFromFileHandle ||
		!pfn_CryptCATAdminAcquireContext ||
		!pfn_CryptCATAdminEnumCatalogFromHash ||
		!pfn_CryptCATCatalogInfoFromContext ||
		!pfn_CryptCATAdminReleaseCatalogContext ||
		!pfn_CryptCATAdminReleaseContext
		)
	{
		return VrUnknown;
	}

	BLPP_VERIFY_RESULT result;
	if (pfn_CryptCATAdminAcquireContext2)
	{
		result = PhpVerifyFileFromCatalog(FileName,L"SHA256");
		if (result != VrTrusted)
			result = PhpVerifyFileFromCatalog(FileName,NULL);
	}
	else
	{
		result = PhpVerifyFileFromCatalog(FileName,NULL);
	}
	return result;
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
