#include <stdio.h>

int main() {
    printf("%ld\n", (1ll * 100 * 0xf0f0f0f0f0f0f0f1) >> 56);
}
