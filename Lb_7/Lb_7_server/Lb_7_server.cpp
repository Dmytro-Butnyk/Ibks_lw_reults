#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <thread>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define PORT "54000"

using namespace std;

struct PacketHeader {
    DWORD magic = 0xDEADBEEF;
    DWORD fileSize;
    BYTE iv[16];
};

void HandleClient(SOCKET clientSocket) {
    BCRYPT_ALG_HANDLE hEcdhAlg = NULL;
    BCRYPT_KEY_HANDLE hKeyPair = NULL, hClientKey = NULL;
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hAesKey = NULL;
    
    vector<BYTE> serverPubKey, clientPubKey, aesKey(32);
    DWORD cbResult = 0;

    BCryptOpenAlgorithmProvider(&hEcdhAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(hEcdhAlg, &hKeyPair, 256, 0);
    BCryptFinalizeKeyPair(hKeyPair, 0);

    DWORD pubKeyLen = 0;
    BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &pubKeyLen, 0);
    serverPubKey.resize(pubKeyLen);
    BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, serverPubKey.data(), pubKeyLen, &pubKeyLen, 0);

    DWORD clientKeyLen = 0;
    recv(clientSocket, (char*)&clientKeyLen, sizeof(DWORD), 0);
    clientPubKey.resize(clientKeyLen);
    recv(clientSocket, (char*)clientPubKey.data(), clientKeyLen, 0);

    send(clientSocket, (char*)&pubKeyLen, sizeof(DWORD), 0);
    send(clientSocket, (char*)serverPubKey.data(), pubKeyLen, 0);

    BCryptImportKeyPair(hEcdhAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hClientKey, clientPubKey.data(), clientKeyLen, 0);
    BCryptSecretAgreement(hKeyPair, hClientKey, &hSecret, 0);

    BCryptBufferDesc parameterList = { 0 };
    BCryptBuffer hashAlgBuffer;
    hashAlgBuffer.BufferType = KDF_HASH_ALGORITHM;
    hashAlgBuffer.cbBuffer = (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    hashAlgBuffer.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
    parameterList.cBuffers = 1;
    parameterList.pBuffers = &hashAlgBuffer;
    parameterList.ulVersion = BCRYPTBUFFER_VERSION;

    BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &parameterList, aesKey.data(), 32, &cbResult, 0);

    PacketHeader header;
    recv(clientSocket, (char*)&header, sizeof(PacketHeader), 0);
    
    if (header.magic != 0xDEADBEEF) {
        cout << "[!] Invalid packet header!" << endl;
        closesocket(clientSocket);
        return;
    }

    vector<BYTE> encryptedData(header.fileSize);
    int totalReceived = 0;
    while (totalReceived < header.fileSize) {
        int bytes = recv(clientSocket, (char*)encryptedData.data() + totalReceived, header.fileSize - totalReceived, 0);
        if (bytes <= 0) break;
        totalReceived += bytes;
    }

    BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, NULL, 0, aesKey.data(), 32, 0);

    vector<BYTE> decryptedData(encryptedData.size());
    DWORD decryptedLen = 0;
    vector<BYTE> iv(header.iv, header.iv + 16);

    if (NT_SUCCESS(BCryptDecrypt(hAesKey, encryptedData.data(), encryptedData.size(), NULL, iv.data(), iv.size(), decryptedData.data(), decryptedData.size(), &decryptedLen, BCRYPT_BLOCK_PADDING))) {
        decryptedData.resize(decryptedLen);
        ofstream outFile("received_decrypted.txt", ios::binary);
        outFile.write((char*)decryptedData.data(), decryptedData.size());
        cout << "[+] File received and decrypted successfully!" << endl;
    } else {
        cout << "[!] Decryption failed!" << endl;
    }

    BCryptDestroyKey(hAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);
    BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hClientKey);
    BCryptDestroyKey(hKeyPair);
    BCryptCloseAlgorithmProvider(hEcdhAlg, 0);
    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(atoi(PORT));

    bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);

    cout << "[*] Server listening on port " << PORT << "..." << endl;

    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket != INVALID_SOCKET) {
            cout << "[+] Client connected. Spawning thread." << endl;
            thread(HandleClient, clientSocket).detach();
        }
    }

    closesocket(listenSocket);
    WSACleanup();
    return 0;
}