#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

using namespace std;

bool MapFileToMemory(const wstring& filename, HANDLE& hFile, HANDLE& hMap, LPVOID& pBuffer, DWORD& fileSize) {
    hFile = CreateFileW(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) return false;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) return false;

    pBuffer = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    return pBuffer != NULL;
}

void UnmapFile(HANDLE hFile, HANDLE hMap, LPVOID pBuffer) {
    if (pBuffer) UnmapViewOfFile(pBuffer);
    if (hMap) CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

bool SaveToFile(const wstring& filename, const vector<BYTE>& data) {
    ofstream outFile(filename, ios::binary);
    if (!outFile) return false;
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool ReadFromFile(const wstring& filename, vector<BYTE>& data) {
    ifstream inFile(filename, ios::binary | ios::ate);
    if (!inFile) return false;
    streamsize size = inFile.tellg();
    inFile.seekg(0, ios::beg);
    data.resize(size);
    if (inFile.read(reinterpret_cast<char*>(data.data()), size)) return true;
    return false;
}

vector<BYTE> CalculateSHA256(const BYTE* data, DWORD length) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0, cbResult = 0;
    vector<BYTE> hashResult;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbResult, 0))) goto cleanup;
    
    hashResult.resize(cbHash);
    
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, length, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, hashResult.data(), cbHash, 0))) hashResult.clear();

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return hashResult;
}

// --- Шифрування/Розшифрування (AES-256) ---

bool AesEncryptDecrypt(const vector<BYTE>& input, const vector<BYTE>& key, vector<BYTE>& output, bool encrypt) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData = 0;
    bool success = false;
    
    vector<BYTE> iv(16, 0); 

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto cleanup;
    
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) goto cleanup;


    if (encrypt) {
        BCryptEncrypt(hKey, (PUCHAR)input.data(), (ULONG)input.size(), NULL, iv.data(), (ULONG)iv.size(), NULL, 0, &cbData, BCRYPT_BLOCK_PADDING);
        output.resize(cbData);
        if (NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)input.data(), (ULONG)input.size(), NULL, iv.data(), (ULONG)iv.size(), output.data(), (ULONG)output.size(), &cbData, BCRYPT_BLOCK_PADDING))) {
            output.resize(cbData);
            success = true;
        }
    } else {
        BCryptDecrypt(hKey, (PUCHAR)input.data(), (ULONG)input.size(), NULL, iv.data(), (ULONG)iv.size(), NULL, 0, &cbData, BCRYPT_BLOCK_PADDING);
        output.resize(cbData);
        if (NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)input.data(), (ULONG)input.size(), NULL, iv.data(), (ULONG)iv.size(), output.data(), (ULONG)output.size(), &cbData, BCRYPT_BLOCK_PADDING))) {
            output.resize(cbData);
            success = true;
        }
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        wcout << L"Usage:\n"
              << L"  Hash/Sign: cryptong.exe hash <input_file> <password>\n"
              << L"  Verify:    cryptong.exe test <input_file> <signature_file>\n"
              << L"  Encrypt:   cryptong.exe enc <input_file> <password>\n"
              << L"  Decrypt:   cryptong.exe dec <input_file> <password>\n";
        return 1;
    }

    wstring action = argv[1];
    wstring inputFile = argv[2];
    
    HANDLE hFile = INVALID_HANDLE_VALUE, hMap = NULL;
    LPVOID pBuffer = NULL;
    DWORD fileSize = 0;

    if (!MapFileToMemory(inputFile, hFile, hMap, pBuffer, fileSize)) {
        wcout << L"[!] Failed to open or map input file.\n";
        return 1;
    }

    vector<BYTE> inputData((BYTE*)pBuffer, (BYTE*)pBuffer + fileSize);

    if (action == L"hash") {
        vector<BYTE> hash = CalculateSHA256((BYTE*)pBuffer, fileSize);
        
        wstring sigFile = inputFile + L".sha256";
        if (SaveToFile(sigFile, hash)) {
            wcout << L"[+] Hash calculated and saved to: " << sigFile << L"\n";
        } else {
            wcout << L"[!] Failed to save hash file.\n";
        }
    } 
    else if (action == L"test") {
        wstring sigFile = argv[3];
        vector<BYTE> savedHash;
        
        if (!ReadFromFile(sigFile, savedHash)) {
            wcout << L"[!] Failed to read signature file.\n";
            UnmapFile(hFile, hMap, pBuffer);
            return 1;
        }

        vector<BYTE> currentHash = CalculateSHA256((BYTE*)pBuffer, fileSize);
        
        if (currentHash == savedHash) {
            wcout << L"[+] Signature is VALID. The file has not been modified.\n";
        } else {
            wcout << L"[-] Signature is INVALID. The file is corrupted or modified.\n";
        }
    }
    else if (action == L"enc" || action == L"dec") {
        wstring password = argv[3];
        
        const BYTE* passData = reinterpret_cast<const BYTE*>(password.c_str());
        DWORD passSize = static_cast<DWORD>(password.size() * sizeof(wchar_t));
        
        vector<BYTE> aesKey = CalculateSHA256(passData, passSize);

        vector<BYTE> outputData;
        bool isEncrypt = (action == L"enc");

        if (AesEncryptDecrypt(inputData, aesKey, outputData, isEncrypt)) {
            wstring outputFile = isEncrypt ? inputFile + L".enc" : inputFile + L".dec";
            if (SaveToFile(outputFile, outputData)) {
                wcout << L"[+] Operation '" << action << L"' successful.\n";
                wcout << L"[+] Output saved to: " << outputFile << L"\n";
            } else {
                wcout << L"[!] Failed to save output file.\n";
            }
        } else {
            wcout << L"[!] Cryptographic operation failed. Check your password or data.\n";
        }
    } else {
        wcout << L"[!] Unknown action. Use hash, test, enc, or dec.\n";
    }

    UnmapFile(hFile, hMap, pBuffer);
    return 0;
}