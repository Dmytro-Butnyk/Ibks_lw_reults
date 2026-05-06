#include <windows.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <string>
#include <locale.h>
#include <vector>

#pragma comment (lib, "wintrust.lib")

using namespace std;

const wstring REG_KEY_PATH = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";
const wstring REG_VALUE_NAME = L"AppCertLab";

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

void ScanCurrentProcesses() {
    wcout << L"[*] Scanning current processes for invalid signatures..." << endl;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
            if (hModuleSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(MODULEENTRY32W);
                if (Module32FirstW(hModuleSnap, &me)) {
                    if (!VerifyFileSignature(me.szExePath)) {
                        wcout << L"[-] PID: " << pe.th32ProcessID << L" | Unsigned/Invalid: " << me.szExePath << endl;
                    }
                }
                CloseHandle(hModuleSnap);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

void CleanupRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, REG_VALUE_NAME.c_str());
        RegCloseKey(hKey);
        wcout << L"\n[*] Registry cleaned up successfully." << endl;
    }
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        CleanupRegistry();
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

bool RegisterAppCertDll(const wstring& dllPath) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        wcout << L"[!] Failed to open/create registry key. RUN AS ADMINISTRATOR!" << endl;
        return false;
    }

    if (RegSetValueExW(hKey, REG_VALUE_NAME.c_str(), 0, REG_EXPAND_SZ, (const BYTE*)dllPath.c_str(), (dllPath.length() + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) {
        wcout << L"[!] Failed to set registry value." << endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    wcout << L"[+] DLL injected into AppCertDlls." << endl;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    
    setlocale(LC_ALL, "");
    
    if (argc < 2) {
        wcout << L"Usage: monitor.exe <Full_Path_to_appcert.dll>" << endl;
        return 1;
    }

    wstring dllPath = argv[1];

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    
    ScanCurrentProcesses();

    if (!RegisterAppCertDll(dllPath)) {
        return 1;
    }

    wcout << L"[*] Entering monitoring mode. Press Ctrl+C to stop and cleanup..." << endl;

    while (true) {
        HANDLE hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\AppCertLogPipe", PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 0, 1024, 0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            if (ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)) {
                WCHAR buffer[1024] = { 0 };
                DWORD bytesRead;
                if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(WCHAR), &bytesRead, NULL)) {
                    wcout << L"AppCert: " << buffer << endl;
                }
            }
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    return 0;
}