#include <stdio.h>

int is_prime(unsigned char k) {
    for (char d = 2; d * d < k; ++d) {
        if (k % d == 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    unsigned char n;
    fread(&n, sizeof(n), 1, stdin);

    if (n < 27) {
        printf("too small");
        return 1;
    }

    if (n > 42) {
        printf("too big");
        return 1;
    }

    if (!is_prime(n)) {
        printf("too ugly");
        return 1;
    }

    printf("Good: %d\n", n);
    return 0;
}
