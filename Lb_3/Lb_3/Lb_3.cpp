#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <wmmintrin.h>

using namespace std;

// Функція для генерації раундових ключів AES-128
#define AES_128_key_exp(k, rcon) _mm_aeskeygenassist_si128(k, rcon)

static __m128i key_expansion_step(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

// Завантаження ключів для шифрування
void AES_128_Key_Expansion(const unsigned char* userkey, __m128i* roundKeys) {
    roundKeys[0] = _mm_loadu_si128((const __m128i*)userkey);
    roundKeys[1] = key_expansion_step(roundKeys[0], AES_128_key_exp(roundKeys[0], 0x01));
    roundKeys[2] = key_expansion_step(roundKeys[1], AES_128_key_exp(roundKeys[1], 0x02));
    roundKeys[3] = key_expansion_step(roundKeys[2], AES_128_key_exp(roundKeys[2], 0x04));
    roundKeys[4] = key_expansion_step(roundKeys[3], AES_128_key_exp(roundKeys[3], 0x08));
    roundKeys[5] = key_expansion_step(roundKeys[4], AES_128_key_exp(roundKeys[4], 0x10));
    roundKeys[6] = key_expansion_step(roundKeys[5], AES_128_key_exp(roundKeys[5], 0x20));
    roundKeys[7] = key_expansion_step(roundKeys[6], AES_128_key_exp(roundKeys[6], 0x40));
    roundKeys[8] = key_expansion_step(roundKeys[7], AES_128_key_exp(roundKeys[7], 0x80));
    roundKeys[9] = key_expansion_step(roundKeys[8], AES_128_key_exp(roundKeys[8], 0x1B));
    roundKeys[10] = key_expansion_step(roundKeys[9], AES_128_key_exp(roundKeys[9], 0x36));
}

// Конвертація ключів для дешифрування
void AES_128_Key_Expansion_Decrypt(__m128i* encRoundKeys, __m128i* decRoundKeys) {
    decRoundKeys[0] = encRoundKeys[10];
    for (int i = 1; i < 10; i++) {
        decRoundKeys[i] = _mm_aesimc_si128(encRoundKeys[10 - i]);
    }
    decRoundKeys[10] = encRoundKeys[0];
}

// Шифрування одного 128-бітного блоку
__m128i AES_128_Encrypt_Block(__m128i m, const __m128i* roundKeys) {
    m = _mm_xor_si128(m, roundKeys[0]);
    for (int i = 1; i < 10; i++) {
        m = _mm_aesenc_si128(m, roundKeys[i]);
    }
    m = _mm_aesenclast_si128(m, roundKeys[10]);
    return m;
}

// Дешифрування одного 128-бітного блоку
__m128i AES_128_Decrypt_Block(__m128i c, const __m128i* decRoundKeys) {
    c = _mm_xor_si128(c, decRoundKeys[0]);
    for (int i = 1; i < 10; i++) {
        c = _mm_aesdec_si128(c, decRoundKeys[i]);
    }
    c = _mm_aesdeclast_si128(c, decRoundKeys[10]);
    return c;
}

void ProcessFile(const string& mode, const string& inputFile, const string& outputFile, const string& keyStr) {
    // Підготовка 128-бітного ключа (заповнюємо нулями, якщо коротший)
    unsigned char key[16] = {0};
    size_t keyLen = keyStr.length() > 16 ? 16 : keyStr.length();
    memcpy(key, keyStr.c_str(), keyLen);

    // Зчитуємо вхідний файл повністю в буфер
    ifstream inFile(inputFile, ios::binary | ios::ate);
    if (!inFile.is_open()) {
        cerr << "Помилка відкриття вхідного файлу: " << inputFile << endl;
        return;
    }
    
    streamsize size = inFile.tellg();
    inFile.seekg(0, ios::beg);
    vector<unsigned char> buffer(size);
    if (inFile.read((char*)buffer.data(), size)) {
    }
    inFile.close();

    // Доповнюємо нулями (Zero Padding), якщо розмір не кратний 16
    size_t remainder = buffer.size() % 16;
    if (remainder != 0) {
        size_t padLen = 16 - remainder;
        buffer.insert(buffer.end(), padLen, 0);
    }

    // Підготовка ключів
    __m128i encRoundKeys[11];
    AES_128_Key_Expansion(key, encRoundKeys);

    __m128i decRoundKeys[11];
    if (mode == "-dec") {
        AES_128_Key_Expansion_Decrypt(encRoundKeys, decRoundKeys);
    }

    // Обробка даних
    vector<unsigned char> outBuffer(buffer.size());
    for (size_t i = 0; i < buffer.size(); i += 16) {
        __m128i block = _mm_loadu_si128((const __m128i*)(buffer.data() + i));
        
        if (mode == "-enc") {
            block = AES_128_Encrypt_Block(block, encRoundKeys);
        } else if (mode == "-dec") {
            block = AES_128_Decrypt_Block(block, decRoundKeys);
        }

        _mm_storeu_si128((__m128i*)(outBuffer.data() + i), block);
    }

    // Запис у вихідний файл
    ofstream outFile(outputFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "Помилка створення вихідного файлу: " << outputFile << endl;
        return;
    }
    outFile.write((char*)outBuffer.data(), outBuffer.size());
    outFile.close();

    cout << "Операція " << (mode == "-enc" ? "шифрування" : "дешифрування") 
         << " успішно завершена. Файл збережено: " << outputFile << endl;
}

int main(int argc, char* argv[]) {
    // Перевірка аргументів: aescipher.exe <-enc | -dec> <input file> <output file> <key>
    if (argc != 5) {
        cout << "Використання: aescipher.exe <-enc | -dec> <input_file> <output_file> <key>" << endl;
        return 1;
    }

    string mode = argv[1];
    string inputFile = argv[2];
    string outputFile = argv[3];
    string key = argv[4];

    if (mode != "-enc" && mode != "-dec") {
        cerr << "Невідомий режим. Використовуйте -enc для шифрування або -dec для дешифрування." << endl;
        return 1;
    }

    ProcessFile(mode, inputFile, outputFile, key);

    return 0;
}