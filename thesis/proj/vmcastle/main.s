.global  _start
.intel_syntax noprefix

.data
msg:
    .asciz "Hello, World!\n"
len:
    .dc.l  . - msg # length of msg

.text

_start:
    xor rax, rax
    inc rax
    shl rax, 0x20
    inc eax
    shl eax, 0x10
    inc ax
    shl ax, 9
    xor al, al
    sub al, 1
    shr al, 8
    inc al
    shl al, 7
    shl al, 1

    mov rax, 60
    mov rdi, 42
    syscall
