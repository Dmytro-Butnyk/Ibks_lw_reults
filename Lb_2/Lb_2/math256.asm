; math256.asm
.code

; void Add256(unsigned long long* res, const unsigned long long* a, const unsigned long long* b)
; RCX = res, RDX = a, R8 = b
Add256 PROC
    mov rax, [rdx]
    add rax, [r8]
    mov [rcx], rax

    mov rax, [rdx+8]
    adc rax, [r8+8]
    mov [rcx+8], rax

    mov rax, [rdx+16]
    adc rax, [r8+16]
    mov [rcx+16], rax

    mov rax, [rdx+24]
    adc rax, [r8+24]
    mov [rcx+24], rax

    ret
Add256 ENDP

; void Sub256(unsigned long long* res, const unsigned long long* a, const unsigned long long* b)
; RCX = res, RDX = a, R8 = b
Sub256 PROC
    mov rax, [rdx]
    sub rax, [r8]
    mov [rcx], rax

    mov rax, [rdx+8]
    sbb rax, [r8+8]
    mov [rcx+8], rax

    mov rax, [rdx+16]
    sbb rax, [r8+16]
    mov [rcx+16], rax

    mov rax, [rdx+24]
    sbb rax, [r8+24]
    mov [rcx+24], rax

    ret
Sub256 ENDP

; int Cmp256(const unsigned long long* a, const unsigned long long* b)
; Returns 1 if a > b, -1 if a < b, 0 if a == b
; RCX = a, RDX = b
Cmp256 PROC
    mov rax, [rcx+24]
    cmp rax, [rdx+24]
    ja a_greater
    jb b_greater

    mov rax, [rcx+16]
    cmp rax, [rdx+16]
    ja a_greater
    jb b_greater

    mov rax, [rcx+8]
    cmp rax, [rdx+8]
    ja a_greater
    jb b_greater

    mov rax, [rcx]
    cmp rax, [rdx]
    ja a_greater
    jb b_greater

    mov eax, 0
    ret
a_greater:
    mov eax, 1
    ret
b_greater:
    mov eax, -1
    ret
Cmp256 ENDP

; void Inc256(unsigned long long* a)
; RCX = a
Inc256 PROC
    add qword ptr [rcx], 1
    adc qword ptr [rcx+8], 0
    adc qword ptr [rcx+16], 0
    adc qword ptr [rcx+24], 0
    ret
Inc256 ENDP

; void Dec256(unsigned long long* a)
; RCX = a
Dec256 PROC
    sub qword ptr [rcx], 1
    sbb qword ptr [rcx+8], 0
    sbb qword ptr [rcx+16], 0
    sbb qword ptr [rcx+24], 0
    ret
Dec256 ENDP

; void Shl256_1(unsigned long long* a)
; Shift left by 1 bit
; RCX = a
Shl256_1 PROC
    shl qword ptr [rcx], 1
    rcl qword ptr [rcx+8], 1
    rcl qword ptr [rcx+16], 1
    rcl qword ptr [rcx+24], 1
    ret
Shl256_1 ENDP

; void Shr256_1(unsigned long long* a)
; Shift right by 1 bit
; RCX = a
Shr256_1 PROC
    shr qword ptr [rcx+24], 1
    rcr qword ptr [rcx+16], 1
    rcr qword ptr [rcx+8], 1
    rcr qword ptr [rcx], 1
    ret
Shr256_1 ENDP

END