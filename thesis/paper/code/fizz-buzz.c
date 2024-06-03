#include <stdio.h>

int main() {
    unsigned char c;
    fread(&c, 1, 1, stdin);

    if (c < 1) {
        printf("too small");
        return 0;
    }

    if (c > 15) {
        printf("too big");
        return 0;
    }

    if (c % 3 == 0 || c % 5 == 0) {
        if (c % 3 == 0)
            printf("fizz");
        if (c % 5 == 0) 
            printf("buzz");
    } else {
        printf("%d", c);
    }
}
