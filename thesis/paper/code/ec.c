#include <stdio.h>

void foo(int a, int b) {
    if (b != 1) {
        int c = 2 * a + 3 * b;
        if (c != 5) {
            puts("fail");
        } else if (a == b + 1) {
            puts("correct");
        }
    } else {
        puts("fail");
    }
}

int main() {
    int a, b;
    scanf("%d %d", &a, &b);
    foo(a, b);
}
