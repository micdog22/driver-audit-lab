
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

static BOOL verify_signature(LPCWSTR path) {
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data = {0};
    data.cbStruct = sizeof(data);
    data.pPolicyCallbackData = NULL;
    data.pSIPClientData = NULL;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG; // basic verification
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &data);
    return status == ERROR_SUCCESS;
}

static void get_file_version(const wchar_t* path, wchar_t* company, size_t companyCch, wchar_t* filever, size_t fileverCch) {
    DWORD handle = 0, size = GetFileVersionInfoSizeW(path, &handle);
    if (size == 0) { company[0]=0; filever[0]=0; return; }
    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) { company[0]=0; filever[0]=0; return; }
    if (GetFileVersionInfoW(path, 0, size, buf)) {
        struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
        UINT cbTranslate = 0;
        if (VerQueryValueW(buf, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) && cbTranslate >= sizeof(*lpTranslate)) {
            wchar_t subBlock[64];
            wchar_t* val = NULL; UINT cch = 0;
            StringCchPrintfW(subBlock, 64, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
            if (VerQueryValueW(buf, subBlock, (LPVOID*)&val, &cch) && val) StringCchCopyW(company, companyCch, val); else company[0]=0;
            VS_FIXEDFILEINFO* ffi = NULL; UINT cb = 0;
            if (VerQueryValueW(buf, L"\\", (LPVOID*)&ffi, &cb) && ffi && ffi->dwSignature == 0xFEEF04BD) {
                WORD ms1 = HIWORD(ffi->dwFileVersionMS), ms2 = LOWORD(ffi->dwFileVersionMS);
                WORD ls1 = HIWORD(ffi->dwFileVersionLS), ls2 = LOWORD(ffi->dwFileVersionLS);
                StringCchPrintfW(filever, fileverCch, L"%hu.%hu.%hu.%hu", ms1, ms2, ls1, ls2);
            } else filever[0]=0;
        } else { company[0]=0; filever[0]=0; }
    }
    free(buf);
}

int wmain(int argc, wchar_t** argv) {
    FILE* csv = NULL;
    if (argc >= 3 && wcscmp(argv[1], L"--csv") == 0) {
        csv = _wfopen(argv[2], L"w, ccs=UTF-8");
        if (csv) fwprintf(csv, L"Base,Path,Signed,Company,FileVersion\n");
    }

    LPVOID drivers[4096];
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        wprintf(L"EnumDeviceDrivers falhou (%lu)\n", GetLastError());
        return 1;
    }
    int count = (int)(needed / sizeof(drivers[0]));
    for (int i=0; i<count; i++) {
        wchar_t path[MAX_PATH]; path[0]=0;
        if (GetDeviceDriverFileNameW(drivers[i], path, MAX_PATH) == 0) continue;
        BOOL signedYes = verify_signature(path);
        wchar_t company[256], ver[64];
        get_file_version(path, company, 256, ver, 64);
        wprintf(L"%p | %s | Signed: %s | Company: %s | FileVer: %s\n",
            drivers[i], path, signedYes?L"YES":L"NO", company, ver);
        if (csv) fwprintf(csv, L"%p,%s,%s,%s,%s\n", drivers[i], path, signedYes?L"YES":L"NO", company, ver);
    }

    if (csv) fclose(csv);
    return 0;
}
