#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

using namespace std;

// Перетворення масиву байтів у шістнадцятковий рядок
string BytesToHexString(const vector<BYTE>& bytes) {
    string hexStr;
    const char hexChars[] = "0123456789abcdef";
    for (BYTE b : bytes) {
        hexStr += hexChars[(b >> 4) & 0x0F];
        hexStr += hexChars[b & 0x0F];
    }
    return hexStr;
}

// Обчислення SHA-256 за допомогою Windows CNG з підтримкою Memory Mapping
bool CalculateFileSHA256(const string& filePath, string& outHashStr) {
    // 1. Відкриття файлу
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Помилка відкриття файлу: " << filePath << endl;
        return false;
    }

    // Отримання розміру файлу
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    if (fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        cerr << "Файл порожній." << endl;
        return false;
    }

    // 2. Створення File Mapping (Відображення на пам'ять)
    HANDLE hMapFile = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapFile == NULL) {
        cerr << "Помилка створення File Mapping." << endl;
        CloseHandle(hFile);
        return false;
    }

    // 3. Відображення файлу в адресний простір
    LPCVOID pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    if (pMapAddress == NULL) {
        cerr << "Помилка MapViewOfFile." << endl;
        CloseHandle(hMapFile);
        CloseHandle(hFile);
        return false;
    }

    // 4. Ініціалізація CNG для SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    PBYTE pbHashObject = NULL;
    vector<BYTE> hashBuffer;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) goto Cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) goto Cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0) != 0) goto Cleanup;

    pbHashObject = new BYTE[cbHashObject];
    hashBuffer.resize(cbHash);

    if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0) goto Cleanup;

    // 5. Хешування даних (безпосередньо з пам'яті за допомогою вказівника)
    if (BCryptHashData(hHash, (PBYTE)pMapAddress, (ULONG)fileSize.QuadPart, 0) != 0) goto Cleanup;

    // Отримання фінального хешу
    if (BCryptFinishHash(hHash, hashBuffer.data(), cbHash, 0) != 0) goto Cleanup;

    outHashStr = BytesToHexString(hashBuffer);

Cleanup:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) delete[] pbHashObject;

    // Звільнення ресурсів файлу
    UnmapViewOfFile(pMapAddress);
    CloseHandle(hMapFile);
    CloseHandle(hFile);

    return !outHashStr.empty();
}

int main(int argc, char* argv[]) {
    // Встановлюємо українське кодування для консолі
    SetConsoleOutputCP(CP_UTF8);

    if (argc != 2) {
        cout << "Використання: Lb_4.exe <шлях_до_вхідного_файлу>" << endl;
        return 1;
    }

    string inputFile = argv[1];
    string hashValue;

    cout << "Хешування файлу: " << inputFile << " ..." << endl;

    if (CalculateFileSHA256(inputFile, hashValue)) {
        string outputFile = inputFile + ".sha256";
        
        // Збереження хешу у файл .sha256
        ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << hashValue;
            outFile.close();
            cout << "Хеш успішно обчислено (SHA-256): " << hashValue << endl;
            cout << "Результат збережено у файл: " << outputFile << endl;
        } else {
            cerr << "Помилка запису у файл " << outputFile << endl;
        }
    } else {
        cerr << "Не вдалося обчислити хеш." << endl;
        return 1;
    }

    return 0;
}