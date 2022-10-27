#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>

const int pagesize = 4096;

void handler(int sig, siginfo_t *info, void *ucontext) {
    printf("Got SIGSEV at addr 0x%lx\n", (long) info->si_addr);

    long aligned = (long)info->si_addr - (long)info->si_addr % pagesize;
    mprotect((void*)aligned, pagesize, PROT_WRITE);

    printf("Changed rights to write\n");
}

int main() {

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    sigaction(SIGSEGV, &sa, NULL);

    void* zone = (int*) mmap(NULL, pagesize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 

    void* inside_pointer = zone + 1024;

    // attempt to write
    *(int*)inside_pointer = 8;
    printf("%d\n", *(int*)inside_pointer);
}
