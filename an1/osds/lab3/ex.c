#include <string.h>
#include <unistd.h>

int sw = 20;
int func(char * argv) {
    /*while (sw) {*/
        /*sleep(1);*/
        /*sw--;*/
    /*}*/

    char buffer[32];
    strcpy(buffer, argv);

    return 0;
}

int main(int argc, char * argv[]) {
    func(argv[1]);
    return 0;
}
