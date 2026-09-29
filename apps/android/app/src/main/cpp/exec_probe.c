#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("compatforge-uid=%ld\n", (long)getuid());
    return 0;
}
