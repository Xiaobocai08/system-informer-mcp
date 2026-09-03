#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct WinEnum {
    cJSON *arr;
    DWORD pidFilter;
    int visibleOnly;
    int includeChildren;
    unsigned long count;
    unsigned long emitted;
    unsigned long long limit;
} WinEnum;

static void add_window(WinEnum *w, HWND hwnd)
{
    DWORD pid = 0, tid = GetWindowThreadProcessId(hwnd, &pid);
    if (w->pidFilter && pid != w->pidFilter) return;
    if (w->visibleOnly && !IsWindowVisible(hwnd)) return;
    w->count++;
    if (w->limit && w->emitted >= w->limit) return;

    WCHAR title[512]; title[0] = 0;
    GetWindowTextW(hwnd, title, 512);
    if (w->visibleOnly && title[0] == 0) { w->count--; return; }
    WCHAR cls[256]; cls[0] = 0;
    GetClassNameW(hwnd, cls, 256);

    cJSON *o = cJSON_CreateObject();
    char hs[32]; _snprintf_s(hs, sizeof(hs), _TRUNCATE, "0x%llX", (unsigned long long)(ULONG_PTR)hwnd);
    cJSON_AddStringToObject(o, "hwnd", hs);
    ntu_add_w(o, "title", title);
    ntu_add_w(o, "className", cls);
    cJSON_AddNumberToObject(o, "pid", pid);
    cJSON_AddNumberToObject(o, "tid", tid);
    cJSON_AddBoolToObject(o, "visible", IsWindowVisible(hwnd) ? 1 : 0);
    cJSON_AddBoolToObject(o, "minimized", IsIconic(hwnd) ? 1 : 0);
    cJSON_AddBoolToObject(o, "maximized", IsZoomed(hwnd) ? 1 : 0);
    RECT r;
    if (GetWindowRect(hwnd, &r))
    {
        cJSON *rect = cJSON_CreateObject();
        cJSON_AddNumberToObject(rect, "left", r.left);
        cJSON_AddNumberToObject(rect, "top", r.top);
        cJSON_AddNumberToObject(rect, "width", r.right - r.left);
        cJSON_AddNumberToObject(rect, "height", r.bottom - r.top);
        cJSON_AddItemToObject(o, "rect", rect);
    }
    cJSON_AddItemToArray(w->arr, o);
    w->emitted++;
}

static BOOL CALLBACK enum_proc(HWND hwnd, LPARAM lp)
{
    WinEnum *w = (WinEnum *)lp;
    add_window(w, hwnd);
    if (w->includeChildren)
        EnumChildWindows(hwnd, enum_proc, lp);
    return TRUE;
}

/* ---- list_windows --------------------------------------------------------- */
static cJSON *tool_list_windows(const cJSON *args, int *isError)
{
    (void)isError;
    WinEnum w;
    w.arr = cJSON_CreateArray();
    w.pidFilter = (DWORD)mcp_arg_u64(args, "pid", 0, NULL);
    w.visibleOnly = mcp_arg_bool(args, "visible_only", 1);
    w.includeChildren = mcp_arg_bool(args, "include_children", 0);
    w.count = 0; w.emitted = 0;
    w.limit = mcp_arg_u64(args, "limit", 200, NULL);
    EnumWindows(enum_proc, (LPARAM)&w);
    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "total", (double)w.count);
    cJSON_AddNumberToObject(result, "returned", (double)w.emitted);
    cJSON_AddItemToObject(result, "windows", w.arr);
    return result;
}

/* ---- window_action -------------------------------------------------------- */
static cJSON *tool_window_action(const cJSON *args, int *isError)
{
    int found = 0;
    unsigned long long hv = mcp_arg_u64(args, "hwnd", 0, &found);
    if (!found) { *isError = 1; return mcp_err_hint("Pass the window handle \"hwnd\" from list_windows.", "Missing required argument: hwnd"); }
    HWND hwnd = (HWND)(ULONG_PTR)hv;
    if (!IsWindow(hwnd)) { *isError = 1; return mcp_err("0x%llX is not a valid window handle", hv); }
    const char *action = mcp_arg_str(args, "action", NULL);
    if (!action) { *isError = 1; return mcp_err_hint("action: close, minimize, maximize, restore, show, hide, bring_to_front, flash.", "Missing 'action'"); }

    if (!_stricmp(action, "close"))
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    else if (!_stricmp(action, "minimize")) ShowWindow(hwnd, SW_MINIMIZE);
    else if (!_stricmp(action, "maximize")) ShowWindow(hwnd, SW_MAXIMIZE);
    else if (!_stricmp(action, "restore")) ShowWindow(hwnd, SW_RESTORE);
    else if (!_stricmp(action, "show")) ShowWindow(hwnd, SW_SHOW);
    else if (!_stricmp(action, "hide")) ShowWindow(hwnd, SW_HIDE);
    else if (!_stricmp(action, "bring_to_front")) { SetForegroundWindow(hwnd); BringWindowToTop(hwnd); }
    else if (!_stricmp(action, "flash")) { FLASHWINFO fi = { sizeof(fi), hwnd, FLASHW_ALL, 3, 0 }; FlashWindowEx(&fi); }
    else { *isError = 1; return mcp_err_hint("Valid: close, minimize, maximize, restore, show, hide, bring_to_front, flash.", "Unknown action '%s'", action); }
    return mcp_ok("Window action '%s' sent to 0x%llX", action, hv);
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_window_tools[] = {
    { "list_windows", "List windows",
      "Enumerate top-level windows (System Informer 'Windows' view): each window's HWND, title, class name, owning "
      "pid/tid, visibility, minimized/maximized state and screen rectangle. Filter by pid to find a specific app's "
      "windows. Set include_children=true to also walk child controls. Use to map processes to their UI or to get "
      "an HWND for window_action.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Only windows owned by this process.\"},"
      "\"visible_only\":{\"type\":\"boolean\",\"default\":true,\"description\":\"Only visible, titled windows.\"},"
      "\"include_children\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Also enumerate child windows/controls.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":200}"
      "},\"additionalProperties\":false}", 0, tool_list_windows },

    { "window_action", "Window action",
      "GUARDED (confirm=true required). Act on a window by HWND (System Informer window context menu): close "
      "(graceful WM_CLOSE - the polite way to end a GUI app), minimize, maximize, restore, show, hide, "
      "bring_to_front, or flash. Get the HWND from list_windows.",
      "{\"type\":\"object\",\"properties\":{"
      "\"hwnd\":{\"type\":[\"integer\",\"string\"],\"description\":\"Window handle (hex string like \\\"0x10abc\\\").\"},"
      "\"action\":{\"type\":\"string\",\"enum\":[\"close\",\"minimize\",\"maximize\",\"restore\",\"show\",\"hide\",\"bring_to_front\",\"flash\"]},"
      "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true.\"}"
      "},\"required\":[\"hwnd\",\"action\",\"confirm\"],\"additionalProperties\":false}", 1, tool_window_action },
};

void register_window_tools(void)
{
    for (size_t i = 0; i < sizeof(g_window_tools) / sizeof(g_window_tools[0]); i++)
        mcp_register_tool(&g_window_tools[i]);
}
