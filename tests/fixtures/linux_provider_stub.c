/* Version-only synthetic Provider evidence, never a Windows Guest runtime. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(CF_STUB_WINE) == defined(CF_STUB_WINESERVER)
#error "Select exactly one fixture role"
#endif

static int environment_equals(const char *name, const char *expected) {
    const char *value = getenv(name);
    return value != NULL && strcmp(value, expected) == 0;
}

int main(int argc, char **argv) {
    static const char marker[] = "COMPATFORGE_LINUX_PROVIDER_FIXTURE_V1\n";
    char actual[sizeof(marker)];
    FILE *file;
    size_t count;
    int marker_ok;
    if (argc != 2 || strcmp(argv[1], "--version") != 0) {
        return 2;
    }
    if (getenv("PATH") != NULL || getenv("HOME") != NULL ||
        !environment_equals("LANG", "C") || !environment_equals("LC_ALL", "C") ||
        !environment_equals("WINEDEBUG", "-all")) {
        return 3;
    }
    file = fopen("compatforge-linux-provider-fixture.marker", "rb");
    if (file == NULL) {
        return 4;
    }
    count = fread(actual, 1, sizeof(actual), file);
    marker_ok = count == sizeof(marker) - 1 && !ferror(file) &&
                memcmp(actual, marker, sizeof(marker) - 1) == 0;
    if (fclose(file) != 0 || !marker_ok) {
        return 5;
    }
#ifdef CF_STUB_WINE
    if (fputs("wine-11.0\n", stdout) == EOF || fflush(stdout) != 0) {
        return 6;
    }
#else
    if (fputs("Wine 11.0\n", stderr) == EOF || fflush(stderr) != 0) {
        return 6;
    }
#endif
    return 0;
}
