#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

using namespace std;

struct PacketHeader {
    DWORD magic = 0xDEADBEEF;
    DWORD fileSize;
    BYTE iv[16];
};

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wcout << L"Usage: client.exe <Server_IP> <File_to_send>" << endl;
        return 1;
    }

    wstring serverIpStr = argv[1];
    string serverIp(serverIpStr.begin(), serverIpStr.end());
    wstring filePath = argv[2];

    ifstream inFile(filePath, ios::binary | ios::ate);
    if (!inFile) {
        wcout << L"[!] Failed to open file: " << filePath << endl;
        return 1;
    }
    streamsize fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);
    vector<BYTE> fileData(fileSize);
    inFile.read((char*)fileData.data(), fileSize);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(54000);

    if (connect(connectSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "[!] Connection failed." << endl;
        return 1;
    }
    cout << "[+] Connected to server." << endl;

    BCRYPT_ALG_HANDLE hEcdhAlg = NULL;
    BCRYPT_KEY_HANDLE hKeyPair = NULL, hServerKey = NULL;
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    vector<BYTE> clientPubKey, serverPubKey, aesKey(32);

    BCryptOpenAlgorithmProvider(&hEcdhAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(hEcdhAlg, &hKeyPair, 256, 0);
    BCryptFinalizeKeyPair(hKeyPair, 0);

    DWORD pubKeyLen = 0;
    BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &pubKeyLen, 0);
    clientPubKey.resize(pubKeyLen);
    BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, clientPubKey.data(), pubKeyLen, &pubKeyLen, 0);

    send(connectSocket, (char*)&pubKeyLen, sizeof(DWORD), 0);
    send(connectSocket, (char*)clientPubKey.data(), pubKeyLen, 0);

    DWORD serverKeyLen = 0;
    recv(connectSocket, (char*)&serverKeyLen, sizeof(DWORD), 0);
    serverPubKey.resize(serverKeyLen);
    recv(connectSocket, (char*)serverPubKey.data(), serverKeyLen, 0);

    BCryptImportKeyPair(hEcdhAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hServerKey, serverPubKey.data(), serverKeyLen, 0);
    BCryptSecretAgreement(hKeyPair, hServerKey, &hSecret, 0);

    BCryptBufferDesc parameterList = { 0 };
    BCryptBuffer hashAlgBuffer = { (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR)), KDF_HASH_ALGORITHM, (PVOID)BCRYPT_SHA256_ALGORITHM };
    parameterList.cBuffers = 1;
    parameterList.pBuffers = &hashAlgBuffer;
    parameterList.ulVersion = BCRYPTBUFFER_VERSION;

    DWORD cbResult = 0;
    BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &parameterList, aesKey.data(), 32, &cbResult, 0);

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hAesKey = NULL;
    BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, NULL, 0, aesKey.data(), 32, 0);

    PacketHeader header;
    for (int i = 0; i < 16; ++i) header.iv[i] = i; 
    vector<BYTE> iv(header.iv, header.iv + 16);

    DWORD encryptedLen = 0;
    BCryptEncrypt(hAesKey, fileData.data(), fileData.size(), NULL, iv.data(), iv.size(), NULL, 0, &encryptedLen, BCRYPT_BLOCK_PADDING);
    vector<BYTE> encryptedData(encryptedLen);
    
    vector<BYTE> ivCopy(header.iv, header.iv + 16); 
    BCryptEncrypt(hAesKey, fileData.data(), fileData.size(), NULL, ivCopy.data(), ivCopy.size(), encryptedData.data(), encryptedData.size(), &encryptedLen, BCRYPT_BLOCK_PADDING);

    header.fileSize = encryptedLen;
    send(connectSocket, (char*)&header, sizeof(PacketHeader), 0);
    send(connectSocket, (char*)encryptedData.data(), encryptedLen, 0);

    cout << "[+] File encrypted and sent successfully." << endl;

    BCryptDestroyKey(hAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);
    BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hServerKey);
    BCryptDestroyKey(hKeyPair);
    BCryptCloseAlgorithmProvider(hEcdhAlg, 0);
    closesocket(connectSocket);
    WSACleanup();

    return 0;
}