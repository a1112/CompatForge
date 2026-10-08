#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0] || argv[1][0] == '-') return 2;
    char *end = NULL;
    errno = 0;
    unsigned long iterations = strtoul(argv[1], &end, 10);
    if (errno || *end || iterations > 100000000UL) return 2;
    LARGE_INTEGER frequency, start, stop;
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&start)) return 3;
    volatile uint32_t value = UINT32_C(0x12345678);
    for (unsigned long i = 0; i < iterations; ++i)
        value = value * UINT32_C(1664525) + UINT32_C(1013904223);
    if (!QueryPerformanceCounter(&stop) || stop.QuadPart < start.QuadPart) return 3;
    unsigned long long nanos = (unsigned long long)
        ((double)(stop.QuadPart - start.QuadPart) * 1000000000.0 / (double)frequency.QuadPart);
    printf("{\"probe\":\"compatforge-console-v1\",\"iterations\":%lu,"
           "\"checksum\":\"%08lx\",\"workNanoseconds\":%llu}\n",
           iterations, (unsigned long)value, nanos);
    return fflush(stdout) == 0 ? 0 : 4;
}
