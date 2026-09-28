#include <windows.h>
#include <stdio.h>

volatile int observed = 0;

__declspec(noinline) int inner(int input) {
    int local_value = input + 7;
    observed = local_value;
    return local_value;
}

__declspec(noinline) int outer(int input) {
    return inner(input * 2);
}

int main(void) {
    int result = outer(5);
    printf("result=%d observed=%d\n", result, observed);
    fflush(stdout);
    Sleep(5000);
    RaiseException(0xE0424242, 0, 0, NULL);
    return result == 17 ? 0 : 1;
}
