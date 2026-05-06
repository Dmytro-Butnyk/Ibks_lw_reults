#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>

#pragma comment (lib, "wintrust.lib")

#define STATUS_SUCCESS ((LONG)0x00000000L)
#define APPCERT_IMAGE_OK_TO_RUN 1
#define APPCERT_CREATION_ALLOWED 2
#define APPCERT_CREATION_DENIED 3

BOOL VerifyFileSignature(LPCWSTR FileName) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = FileName;

    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);

    return (status == ERROR_SUCCESS);
}

void LogToConsole(LPCWSTR message) {
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\AppCertLogPipe", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hPipe, message, lstrlenW(message) * sizeof(WCHAR), &bytesWritten, NULL);
        CloseHandle(hPipe);
    }
}

extern "C" __declspec(dllexport) LONG CreateProcessNotify(LPCWSTR lpApplicationName, ULONG uReason) {
    if (uReason == APPCERT_IMAGE_OK_TO_RUN || uReason == APPCERT_CREATION_ALLOWED) {
        if (lpApplicationName != NULL) {
            BOOL isTrusted = VerifyFileSignature(lpApplicationName);
            if (!isTrusted) {
                std::wstring msg = L"[!] INVALID/NO SIGNATURE: ";
                msg += lpApplicationName;
                LogToConsole(msg.c_str());
            }
        }
    }
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}