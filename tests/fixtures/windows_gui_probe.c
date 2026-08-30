#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>

static const wchar_t kClassName[] = L"CompatForgeWin32Probe";
static const wchar_t kWindowTitle[] = L"CompatForge Win32 Probe";
static const wchar_t kProbeText[] = L"CompatForge \x4E2D\x6587\x7A97\x53E3\x6E32\x67D3\x9A8C\x8BC1";

static LRESULT CALLBACK probe_window_proc(HWND window, UINT message, WPARAM word, LPARAM parameter) {
    (void)word;
    (void)parameter;
    switch (message) {
        case WM_PAINT: {
            PAINTSTRUCT paint;
            RECT bounds;
            HDC context = BeginPaint(window, &paint);
            GetClientRect(window, &bounds);
            HFONT font = CreateFontW(
                -32,
                0,
                0,
                0,
                FW_NORMAL,
                FALSE,
                FALSE,
                FALSE,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                ANTIALIASED_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE,
                L"Heiti SC"
            );
            HGDIOBJ previous_font = NULL;
            if (font != NULL) {
                previous_font = SelectObject(context, font);
            }
            SetBkMode(context, TRANSPARENT);
            DrawTextW(context, kProbeText, -1, &bounds, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if (previous_font != NULL) {
                SelectObject(context, previous_font);
            }
            if (font != NULL) {
                DeleteObject(font);
            }
            EndPaint(window, &paint);
            return 0;
        }
        case WM_TIMER:
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, word, parameter);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show) {
    (void)previous;
    (void)command_line;
    (void)show;
    WNDCLASSW window_class = {0};
    window_class.lpfnWndProc = probe_window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    window_class.lpszClassName = kClassName;
    if (RegisterClassW(&window_class) == 0) {
        return 10;
    }
    HWND window = CreateWindowExW(
        0,
        kClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        760,
        420,
        NULL,
        NULL,
        instance,
        NULL
    );
    if (window == NULL) {
        return 11;
    }
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    if (SetTimer(window, 1, 30000, NULL) == 0) {
        DestroyWindow(window);
        return 12;
    }
    MSG message;
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return (int)message.wParam;
}
