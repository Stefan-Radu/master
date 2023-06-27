#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

const char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                        "\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(int argc, char *argv[]) {
    void *p = mmap(NULL, 4096, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    size_t len = strlen(shellcode);
    strncpy(p, shellcode, len);

    int (*fct)() = p;

    fct();
    return 0;
}
