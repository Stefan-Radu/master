/* =================== 3.1
myst2:
    cmp BYTE PTR [rdi], 0
    je .L4
    mov eax, 0
.L3:
    add rax, 1
    cmp BYTE PTR [rdi+rax], 0
    jne .L3
    ret
.L4:
    mov eax, 0
    ret
*/

int foo1(char* rdi) {
    int i = 0;
    while (rdi[i] != 0) {
        ++i;
    }
    return i;
}

/* =============== 3.2
myst4:
    push rbp
    push rbx
    sub rsp, 8
    mov rbx, rdi
    cmp rdi, 1
    ja .L4
.L2:
    mov rax, rbx
    add rsp, 8
    pop rbx
    pop rbp
    ret
.L4:
    lea rdi, [rdi-1]
    call myst4
    mov rbp, rax
    lea rdi, [rbx-2]
    call myst4
    lea rbx, [rbp+0+rax]
    jmp .L2
*/

long myst4(long rdi) {
    // save old rbp
    // save old rbx (preserve its value and use it in the function for calculations)
    // allocate 8 bytes on the stack
    long rbx = rdi;
    if (rdi > 1) {
        rdi -= 1; // weird usage of LEA
        long rbp = myst4(rdi);
        rdi = rbx - 2;
        rbx = rbp + myst4(rdi);
        rdi = rbx;
    }

    // restore everything
    return rdi;
}

long myst4_frumos(long rdi) {
    // fibonacci
    if (rdi <= 1) {
        return rdi;
    }
    return myst4_frumos(rdi - 1) + myst4_frumos(rdi - 2);
}

/* ============= 3.3
myst5:
    xor eax, eax     => eax = 0
    cmp rdi, 1       => if rdi <= 1
    jbe .L1          =>   ret 0
    cmp rdi, 3       => if rdi <= 3
    jbe .L6          =>  ret 1
    test dil, 1      => if (rdi & 1) == 0
    je .L1           =>  ret 0 
    mov ecx, 2       => rcx = 2
    jmp .L3          => goto L3
.L4:
    mov rax, rdi        rax = rdi
    xor edx, edx        edx = 0
    div rcx             
    test rdx, rdx       if (rax % rcx == 0)
    je .L8                return 0
.L3:
    add rcx, 1          rcx += 1
    mov rax, rcx        rax = rcx
    imul rax, rcx       rax *= rcx
    cmp rax, rdi        if rax <= rdi
    jbe .L4                 goto L4
.L6:                    else
    mov eax, 1              ret 1
    ret
.L8:
    xor eax, eax
.L1:
    ret
*/

int myst5(long rdi) { // prime number checker
    if (rdi <= 1) return 0;
    if (rdi <= 3) return 1;
    if (rdi % 2 == 0) return 0;

    for (int d = 3; d * d <= rdi; ++d) {
        if (rdi % d == 0) {
            return 0;
        }
    }
    return 1;
}

/* 
 * BONUS 1
 
my_function:
    movabs rdx, -1085102592571150095 ==> 0xf0f0f0f0f0f0f0f1
    mov rax, rdi        ==> ia valoarea primului argument din functie
    mul rdx             ==> rax *= rdx (inmuntesc primul argument cu constanta)
    mov rax, rdx        ==> (capturez overflow-ul)
    shr rax, 4          ==> impart la 16
    ret                 ==> (return overflow fara ultimii 4 biti)
*/

// BONUS 2
// modify address 0x109d ==> 74 -> 75 (JE -> JNE)
// input 3449424416 (0xcd9a0a20)
