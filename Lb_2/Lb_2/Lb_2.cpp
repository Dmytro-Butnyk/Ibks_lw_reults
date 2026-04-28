#include <iostream>
#include <iomanip>
#include <cstdint>
#include <string>
#include <fstream>
#include <vector>

extern "C" {
    void Add256(uint64_t* res, const uint64_t* a, const uint64_t* b);
    void Sub256(uint64_t* res, const uint64_t* a, const uint64_t* b);
    int Cmp256(const uint64_t* a, const uint64_t* b);
    void Shl256_1(uint64_t* a);
}

struct BigInt256 {
    uint64_t d[4];

    // Ініціалізація нулем за замовчуванням
    BigInt256() { d[0] = 0; d[1] = 0; d[2] = 0; d[3] = 0; }
    
    // Ініціалізація 64-бітним числом
    BigInt256(uint64_t val) { d[0] = val; d[1] = 0; d[2] = 0; d[3] = 0; }

    bool isZero() const { return d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0; }

    // Отримати значення конкретного біта (0..255)
    bool getBit(int i) const { return (d[i / 64] >> (i % 64)) & 1; }

    // Встановити конкретний біт в 1
    void setBit(int i) { d[i / 64] |= (1ULL << (i % 64)); }

    void Print(const char* label) const {
        std::cout << label << "0x";
        for (int i = 3; i >= 0; --i) {
            std::cout << std::hex << std::setw(16) << std::setfill('0') << d[i];
        }
        std::cout << std::dec << std::endl;
    }
};

// Ділення з остачею (Shift-and-Subtract)
// Обчислює: q = a / b; r = a % b
void DivMod(const BigInt256& a, const BigInt256& b, BigInt256& q, BigInt256& r) {
    q = BigInt256();
    r = BigInt256();
    if (b.isZero()) return;

    for (int i = 255; i >= 0; --i) {
        Shl256_1(r.d); 
        if (a.getBit(i)) r.d[0] |= 1;

        if (Cmp256(r.d, b.d) >= 0) { 
            Sub256(r.d, r.d, b.d);   
            q.setBit(i);       
        }
    }
}

// Множення по модулю: (a * b) % n
BigInt256 MulMod(BigInt256 a, BigInt256 b, const BigInt256& n) {
    BigInt256 res;
    for (int i = 0; i < 256; ++i) {
        if (b.getBit(i)) {
            Add256(res.d, res.d, a.d);
            if (Cmp256(res.d, n.d) >= 0) Sub256(res.d, res.d, n.d); 
        }
        Shl256_1(a.d);
        if (Cmp256(a.d, n.d) >= 0) Sub256(a.d, a.d, n.d); 
    }
    return res;
}

// Піднесення до степеня по модулю: (base ^ exp) % n
BigInt256 PowMod(BigInt256 base, BigInt256 exp, const BigInt256& n) {
    BigInt256 res(1);
    BigInt256 b = base;
    for (int i = 0; i < 256; ++i) {
        if (exp.getBit(i)) {
            res = MulMod(res, b, n);
        }
        b = MulMod(b, b, n);
    }
    return res;
}

// Розширений алгоритм Евкліда для пошуку закритого ключа D (Обернене число)
BigInt256 ModInverse(BigInt256 e, BigInt256 phi) {
    BigInt256 t(0), newt(1);
    BigInt256 r = phi, newr = e;

    while (!newr.isZero()) {
        BigInt256 q, rem;
        DivMod(r, newr, q, rem);
        
        r = newr;
        newr = rem;

        BigInt256 q_newt = MulMod(q, newt, phi);
        BigInt256 temp_t = t;
        if (Cmp256(temp_t.d, q_newt.d) < 0) {
            Add256(temp_t.d, temp_t.d, phi.d); 
        }
        Sub256(temp_t.d, temp_t.d, q_newt.d);
        
        t = newt;
        newt = temp_t;
    }
    return t;
}

void EncryptFile(const std::string& inFile, const std::string& outFile, BigInt256 e, BigInt256 n) {
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile);
    
    if(!in) { std::cerr << "Не вдалося відкрити файл для читання!\n"; return; }

    char ch;
    while (in.get(ch)) {
        BigInt256 m((uint64_t)(unsigned char)ch);
        BigInt256 c = PowMod(m, e, n);
        
        out << c.d[3] << " " << c.d[2] << " " << c.d[1] << " " << c.d[0] << "\n";
    }
    in.close(); out.close();
    std::cout << "Файл успішно зашифровано: " << outFile << "\n";
}

void DecryptFile(const std::string& inFile, const std::string& outFile, BigInt256 d, BigInt256 n) {
    std::ifstream in(inFile);
    std::ofstream out(outFile, std::ios::binary);
    
    if(!in) { std::cerr << "Не вдалося відкрити файл для читання!\n"; return; }

    BigInt256 c;
    while (in >> c.d[3] >> c.d[2] >> c.d[1] >> c.d[0]) {
        BigInt256 m = PowMod(c, d, n);
        out.put((char)m.d[0]); 
    }
    in.close(); out.close();
    std::cout << "Файл успішно розшифровано: " << outFile << "\n";
}

int main() {
    std::cout << "--- Лабораторна робота 2: RSA (256-bit ASM) ---" << std::endl;

    BigInt256 p(104729);
    BigInt256 q(104723);
    
    // n = p * q
    BigInt256 n;
    n.d[0] = p.d[0] * q.d[0]; 

    // phi = (p-1) * (q-1)
    BigInt256 phi;
    phi.d[0] = (p.d[0] - 1) * (q.d[0] - 1);

    BigInt256 e(65537); 
    BigInt256 d = ModInverse(e, phi); 

    n.Print("Модуль N     : ");
    e.Print("Відкритий e  : ");
    d.Print("Закритий d   : ");
    std::cout << "-----------------------------------------------" << std::endl;

    std::string originalFile = "message.txt";
    std::ofstream testOut(originalFile);
    testOut << "Hello RSA! This is a test using 256-bit ASM long arithmetic.";
    testOut.close();

    std::string encFile = "encrypted.txt";
    std::string decFile = "decrypted.txt";

    EncryptFile(originalFile, encFile, e, n);
    DecryptFile(encFile, decFile, d, n);

    std::cout << "\n[УСПІХ] Програма завершила роботу. Перевірте файли!" << std::endl;
    return 0;
}