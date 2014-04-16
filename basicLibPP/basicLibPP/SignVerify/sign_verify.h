
#pragma once

#define BLPP_VERIFY_DEFAULT_SIZE_LIMIT (64 * 1024 * 1024)

#define BLPP_VERIFY_PREVENT_NETWORK_ACCESS 0x1
#define BLPP_VERIFY_VIEW_PROPERTIES 0x2

typedef struct _BLPP_VERIFY_FILE_INFO
{
	PWSTR FileName;
	ULONG Flags;

	ULONG FileSizeLimitForHash; // 0 for PH_VERIFY_DEFAULT_SIZE_LIMIT, -1 for unlimited
	ULONG NumberOfCatalogFileNames;
	PWSTR *CatalogFileNames;

	HWND hWnd; // for PH_VERIFY_VIEW_PROPERTIES
} BLPP_VERIFY_FILE_INFO, *PBLPP_VERIFY_FILE_INFO;
