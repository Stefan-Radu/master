#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h> /* for rdtscp and clflush */ 


static int secret = 27;
char *array[256];

static inline void clflush(volatile void *p) {
    asm volatile("clflush %0" : "+m" (*(volatile char *)p));
}

int main() {

    for (int i = 0; i < 256; ++i) {
        array[i] = malloc(4096);
    }

    for (int i = 0; i < 256; ++i) {
        clflush(&array[i][1000]);
    }

    array[secret][1000] += 1;

    long long t;
    unsigned int junk, jk;

    junk = array[secret][1000];

    for (int i = 0; i < 256; ++i) {
        t = __rdtscp(&jk);
        junk = array[i][1000];
        printf("Accessed %d in: %lld\n", i, __rdtscp(&jk) - t);
    }
}
