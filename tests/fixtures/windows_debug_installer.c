#include <windows.h>

/* Test-only installer for a managed generation in the isolated ForgeOS VM. */
int main(void) {
    const char *directory = "C:\\Program Files\\Forge Debug Probe";
    const char *source = "Z:\\home\\forge\\forge-debug-probe\\windows_debug_probe.exe";
    const char *installed = "C:\\Program Files\\Forge Debug Probe\\probe.exe";
    if (!CreateDirectoryA(directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return 1;
    }
    return CopyFileA(source, installed, FALSE) ? 0 : 2;
}
