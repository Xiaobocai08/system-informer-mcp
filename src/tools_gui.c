#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <shellapi.h>
#include <shlwapi.h>

static int si_dir(char *out, size_t cap)
{
    char exe[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("SYSTEMINFORMER_PATH", exe, MAX_PATH);
    if (n > 0 && n < MAX_PATH)
    {
        /* strip filename if a full exe path was given */
        char *slash = strrchr(exe, '\\');
        if (slash && StrStrIA(exe, ".exe")) { *slash = 0; }
        _snprintf_s(out, cap, _TRUNCATE, "%s", exe);
        return 1;
    }
    const char *dirs[] = { "C:\\Program Files\\SystemInformer", "C:\\Program Files (x86)\\SystemInformer" };
    for (int i = 0; i < 2; i++)
    {
        char probe[MAX_PATH];
        _snprintf_s(probe, sizeof(probe), _TRUNCATE, "%s\\SystemInformer.exe", dirs[i]);
        if (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES) { _snprintf_s(out, cap, _TRUNCATE, "%s", dirs[i]); return 1; }
    }
    return 0;
}

static cJSON *launch_si(const char *exeName, PCWSTR params, int *isError)
{
    char dir[MAX_PATH];
    if (!si_dir(dir, sizeof(dir)))
    {
        *isError = 1;
        return mcp_err_hint("Install System Informer, or set the SYSTEMINFORMER_PATH environment variable to its folder or SystemInformer.exe.", "System Informer is not installed where I looked (Program Files\\SystemInformer).");
    }
    char exe[MAX_PATH];
    _snprintf_s(exe, sizeof(exe), _TRUNCATE, "%s\\%s", dir, exeName);
    if (GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES)
    {
        *isError = 1;
        return mcp_err("%s was not found in %s", exeName, dir);
    }
    PWSTR wexe = ntu_u2w(exe);
    PWSTR wdir = ntu_u2w(dir);
    SHELLEXECUTEINFOW sei; memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpFile = wexe;
    sei.lpParameters = params;
    sei.lpDirectory = wdir;
    sei.nShow = SW_SHOWNORMAL;
    BOOL ok = ShellExecuteExW(&sei);
    DWORD e = GetLastError();
    cJSON *o;
    if (!ok) { o = ntu_win_error("ShellExecuteEx", e); *isError = 1; }
    else
    {
        o = mcp_ok("Launched %s", exeName);
        cJSON_AddStringToObject(o, "path", exe);
        if (sei.hProcess) { cJSON_AddNumberToObject(o, "pid", GetProcessId(sei.hProcess)); CloseHandle(sei.hProcess); }
    }
    free(wexe); free(wdir);
    return o;
}

/* ---- launch_systeminformer_gui -------------------------------------------- */
static cJSON *tool_launch_gui(const cJSON *args, int *isError)
{
    WCHAR params[64] = L"";
    int pidFound = 0;
    unsigned long long pid = mcp_arg_u64(args, "select_pid", 0, &pidFound);
    if (pidFound)
        _snwprintf_s(params, 64, _TRUNCATE, L"-selectpid %llu", pid);
    return launch_si("SystemInformer.exe", params[0] ? params : NULL, isError);
}

/* ---- launch_peview -------------------------------------------------------- */
static cJSON *tool_launch_peview(const cJSON *args, int *isError)
{
    const char *path = mcp_arg_str(args, "path", NULL);
    if (!path || !path[0]) { *isError = 1; return mcp_err_hint("Pass the \"path\" of the PE file (exe/dll/sys) to open.", "Missing required argument: path"); }
    PWSTR wparams = ntu_u2w(path);
    /* quote the path */
    WCHAR quoted[1024];
    _snwprintf_s(quoted, 1024, _TRUNCATE, L"\"%s\"", wparams);
    free(wparams);
    return launch_si("peview.exe", quoted, isError);
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_gui_tools[] = {
    { "launch_systeminformer_gui", "Open System Informer GUI",
      "Launch the full System Informer desktop application for interactive, graphical inspection (live CPU/IO "
      "graphs, color-coded process tree, property dialogs) that does not translate well to tool output. Optionally "
      "pass select_pid to open with that process selected. Requires System Informer to be installed (see "
      "server_status). This is a hand-off for a human to look at the screen.",
      "{\"type\":\"object\",\"properties\":{"
      "\"select_pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Open with this process selected in the list.\"}"
      "},\"additionalProperties\":false}", 0, tool_launch_gui },

    { "launch_peview", "Open PE Viewer",
      "Open System Informer's PE Viewer (peview.exe) on an executable/DLL/driver to inspect headers, sections, "
      "imports, exports, resources and certificates graphically. Requires System Informer to be installed.",
      "{\"type\":\"object\",\"properties\":{"
      "\"path\":{\"type\":\"string\",\"description\":\"Full path to the PE file to open.\"}"
      "},\"required\":[\"path\"],\"additionalProperties\":false}", 0, tool_launch_peview },
};

void register_gui_tools(void)
{
    for (size_t i = 0; i < sizeof(g_gui_tools) / sizeof(g_gui_tools[0]); i++)
        mcp_register_tool(&g_gui_tools[i]);
}
