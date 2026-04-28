#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>

#pragma comment(lib, "bcrypt.lib")

using namespace std;

// Розмір підпису для RSA-2048 становить 256 байт
const DWORD RSA_SIGNATURE_SIZE = 256;

// Перевірка статусів Windows API
void CheckStatus(NTSTATUS status, const string& msg) {
    if (status != 0) {
        cerr << "Помилка: " << msg << " (Код: " << hex << status << ")" << endl;
        exit(1);
    }
}

// Збереження ключа RSA у файл
void SaveKeyToFile(BCRYPT_KEY_HANDLE hKey, const string& keyFile) {
    DWORD cbBlob = 0;
    // Отримуємо необхідний розмір буфера
    CheckStatus(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &cbBlob, 0), "Отримання розміру ключа");
    
    vector<BYTE> keyBlob(cbBlob);
    CheckStatus(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, keyBlob.data(), cbBlob, &cbBlob, 0), "Експорт ключа");
    
    ofstream out(keyFile, ios::binary);
    if (!out) { cerr << "Помилка відкриття файлу для збереження ключа!" << endl; exit(1); }
    out.write((char*)keyBlob.data(), cbBlob);
    out.close();
    
    cout << "[OK] Ключ збережено у файл: " << keyFile << endl;
}

// Завантаження ключа RSA з файлу
void LoadKeyFromFile(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE* phKey, const string& keyFile) {
    ifstream in(keyFile, ios::binary | ios::ate);
    if (!in) { cerr << "Помилка відкриття файлу ключа для читання!" << endl; exit(1); }
    
    streamsize size = in.tellg();
    in.seekg(0, ios::beg);
    
    vector<BYTE> keyBlob(size);
    in.read((char*)keyBlob.data(), size);
    in.close();
    
    CheckStatus(BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, phKey, keyBlob.data(), (ULONG)size, 0), "Імпорт ключа");
    cout << "[OK] Ключ успішно завантажено з: " << keyFile << endl;
}

// Обчислення хешу SHA-256 з використанням Memory Mapping
vector<BYTE> GetHash(const string& filePath, LONGLONG dataSize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0, cbData = 0;

    CheckStatus(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0), "Відкриття провайдера SHA-256");
    CheckStatus(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0), "Отримання довжини хешу");

    vector<BYTE> hash(cbHash);

    // Memory Mapping
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { cerr << "Не вдалося відкрити файл."; exit(1); }
    
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pData = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, (SIZE_T)dataSize);

    CheckStatus(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0), "Створення об'єкта хешу");
    CheckStatus(BCryptHashData(hHash, (PBYTE)pData, (ULONG)dataSize, 0), "Хешування даних");
    CheckStatus(BCryptFinishHash(hHash, hash.data(), cbHash, 0), "Завершення хешування");

    UnmapViewOfFile(pData);
    CloseHandle(hMap);
    CloseHandle(hFile);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return hash;
}

// Головна логіка ЕЦП
void ProcessEDC(const string& mode, const string& filePath, const string& keyFile) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    // Вказуємо параметри Padding
    BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    CheckStatus(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0), "Відкриття провайдера RSA");

    if (mode == "hash") {
        // 1. Генерація нової пари ключів
        CheckStatus(BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0), "Генерація пари ключів");
        CheckStatus(BCryptFinalizeKeyPair(hKey, 0), "Фіналізація ключа");
        
        // 2. Збереження ключа у файл
        SaveKeyToFile(hKey, keyFile);

        // 3. Хешування файлу
        WIN32_FILE_ATTRIBUTE_DATA attr;
        GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &attr);
        LONGLONG fileSize = ((LONGLONG)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;

        vector<BYTE> hash = GetHash(filePath, fileSize);
        vector<BYTE> signature(RSA_SIGNATURE_SIZE);
        DWORD cbSig = 0;

        // 4. Підписання хешу
        CheckStatus(BCryptSignHash(hKey, &padInfo, hash.data(), (ULONG)hash.size(), signature.data(), (ULONG)signature.size(), &cbSig, BCRYPT_PAD_PKCS1), "Створення підпису");

        // 5. Запис підпису в кінець файлу
        ofstream outFile(filePath, ios::binary | ios::app);
        outFile.write((char*)signature.data(), signature.size());
        outFile.close();
        
        cout << "[OK] ЕЦП успішно додано в кінець файлу: " << filePath << endl;

    } else if (mode == "test") {
        // 1. Завантаження збереженого ключа
        LoadKeyFromFile(hAlg, &hKey, keyFile);

        WIN32_FILE_ATTRIBUTE_DATA attr;
        GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &attr);
        LONGLONG totalSize = ((LONGLONG)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
        
        if (totalSize < RSA_SIGNATURE_SIZE) { cerr << "Файл занадто малий для наявності підпису."; return; }

        LONGLONG dataSize = totalSize - RSA_SIGNATURE_SIZE;
        
        // 2. Хешування файлу без підпису
        vector<BYTE> hash = GetHash(filePath, dataSize);

        // 3. Читання підпису (останні 256 байт)
        vector<BYTE> signature(RSA_SIGNATURE_SIZE);
        ifstream inFile(filePath, ios::binary);
        inFile.seekg(dataSize);
        inFile.read((char*)signature.data(), RSA_SIGNATURE_SIZE);
        inFile.close();

        // 4. Перевірка підпису
        NTSTATUS status = BCryptVerifySignature(hKey, &padInfo, hash.data(), (ULONG)hash.size(), signature.data(), (ULONG)signature.size(), BCRYPT_PAD_PKCS1);
        
        if (status == 0) cout << "\n>>> [VALID] Підпис дійсний! Цілісність та авторство підтверджено." << endl;
        else cout << "\n>>> [INVALID] Підпис невірний або файл було змінено!" << endl;
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

int main(int argc, char* argv[]) {
    // Встановлюємо українське кодування
    SetConsoleOutputCP(CP_UTF8);

    // Новий формат: hash.exe RSA <hash|test> <file> <key_file>
    if (argc < 5) {
        cout << "Використання: lb_5.exe RSA <hash|test> <target_file> <key_file>" << endl;
        cout << "Приклад підпису: lb_5.exe RSA hash test.txt private.key" << endl;
        cout << "Приклад перевірки: lb_5.exe RSA test test.txt private.key" << endl;
        return 1;
    }

    string mode = argv[2];
    string file = argv[3];
    string keyFile = argv[4];

    ProcessEDC(mode, file, keyFile);
    return 0;
}