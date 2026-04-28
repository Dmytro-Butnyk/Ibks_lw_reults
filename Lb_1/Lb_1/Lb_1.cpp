#include <iostream>
#include <iomanip>
#include <cstdint>

// Оголошення зовнішніх асемблерних функцій
extern "C" {
    void Add256(uint64_t* res, const uint64_t* a, const uint64_t* b);
    void Sub256(uint64_t* res, const uint64_t* a, const uint64_t* b);
    int Cmp256(const uint64_t* a, const uint64_t* b);
    void Inc256(uint64_t* a);
    void Dec256(uint64_t* a);
    void Shl256_1(uint64_t* a);
    void Shr256_1(uint64_t* a);
}

// Допоміжна функція для виводу 256-бітного числа у форматі Hex
void Print256(const char* label, const uint64_t* a) {
    std::cout << label << "0x";
    for (int i = 3; i >= 0; --i) {
        std::cout << std::hex << std::setw(16) << std::setfill('0') << a[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "--- Лабораторна робота 1: Довга арифметика 256-bit ---" << std::endl;

    // Тестові числа
    uint64_t num1[4] = { 0xFFFFFFFFFFFFFFFF, 0x0, 0x0, 0x0 }; // 2^64 - 1
    uint64_t num2[4] = { 0x2, 0x0, 0x0, 0x0 }; // 2
    uint64_t res[4] = { 0 };

    Print256("Num 1: ", num1);
    Print256("Num 2: ", num2);

    // Додавання
    Add256(res, num1, num2);
    Print256("Add  : ", res);

    // Віднімання
    Sub256(res, num1, num2);
    Print256("Sub  : ", res);

    // Порівняння
    int cmp = Cmp256(num1, num2);
    std::cout << "Cmp(Num1, Num2) : " << cmp << " (1: >, -1: <, 0: ==)" << std::endl;

    // Інкремент
    Inc256(num1);
    Print256("Inc(Num1) : ", num1);

    // Зсув вліво на 1 біт (x2)
    Shl256_1(num2);
    Print256("Shl(Num2) : ", num2);

    std::cout << "------------------------------------------------------" << std::endl;
    return 0;
}