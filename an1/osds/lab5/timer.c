#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h> /* for rdtscp and clflush */ 

static inline void clflush(volatile void *p) {
    asm volatile("clflush %0" : "+m" (*(volatile char *)p));
}

int v[1000000];

int main() {
    memset(v, 1, sizeof(v[0]));

    unsigned int junk;
    long long t = __rdtscp(&junk);
    int s = 0;
    for (int i = 0; i < 64; ++i) {
        for (int j = 0; j < 1000000; ++j) {
            s += v[j];
        }
    }
    printf("time elapsed no flush:    %lld\n", __rdtscp(&junk) - t);
    fflush(stdout);

    t = __rdtscp(&junk);
    s = 0;
    for (int i = 0; i < 64; ++i) {
        for (int j = 0; j < 1000000; ++j) {
            clflush(v + j);
            s += v[j];
        }
    }

    printf("time elapsed with flush: %lld", __rdtscp(&junk) - t);
}
