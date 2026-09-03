#include "ntutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* ---- time ----------------------------------------------------------------- */
void ntu_time_to_iso(LONG64 timestamp100ns, char *out, size_t cap)
{
    if (cap == 0)
        return;
    if (timestamp100ns == 0)
    {
        out[0] = '\0';
        return;
    }
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(ULONG64)timestamp100ns;
    ft.dwHighDateTime = (DWORD)((ULONG64)timestamp100ns >> 32);
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st))
    {
        out[0] = '\0';
        return;
    }
    _snprintf_s(out, cap, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void ntu_now_iso(char *out, size_t cap)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    LONG64 v = ((LONG64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    ntu_time_to_iso(v, out, cap);
}

/* ---- strings -------------------------------------------------------------- */
char *ntu_w2u(PCWSTR w, int cch)
{
    if (!w || cch == 0)
        return NULL;
    int len = WideCharToMultiByte(CP_UTF8, 0, w, cch, NULL, 0, NULL, NULL);
    if (len <= 0)
        return NULL;
    size_t bufSize = (cch == -1) ? (size_t)len : (size_t)len + 1;
    char *out = (char *)malloc(bufSize);
    if (!out)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, cch, out, len, NULL, NULL);
    if (cch != -1)
        out[len] = '\0';
    return out;
}

PWSTR ntu_u2w(const char *s)
{
    if (!s)
        return NULL;
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (len <= 0)
        return NULL;
    PWSTR out = (PWSTR)malloc((size_t)len * sizeof(WCHAR));
    if (!out)
        return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, len);
    return out;
}

void ntu_add_w(cJSON *obj, const char *key, PCWSTR w)
{
    char *u = ntu_w2u(w, -1);
    if (u)
    {
        cJSON_AddStringToObject(obj, key, u);
        free(u);
    }
    else
    {
        cJSON_AddNullToObject(obj, key);
    }
}

void ntu_add_wn(cJSON *obj, const char *key, PCWSTR w, int cch)
{
    char *u = ntu_w2u(w, cch);
    if (u)
    {
        cJSON_AddStringToObject(obj, key, u);
        free(u);
    }
    else
    {
        cJSON_AddNullToObject(obj, key);
    }
}

void ntu_add_us(cJSON *obj, const char *key, const UNICODE_STRING *us)
{
    if (us && us->Buffer && us->Length)
        ntu_add_wn(obj, key, us->Buffer, (int)(us->Length / sizeof(WCHAR)));
    else
        cJSON_AddNullToObject(obj, key);
}

/* ---- sizes ---------------------------------------------------------------- */
void ntu_bytes_pretty(unsigned long long bytes, char *out, size_t cap)
{
    static const char *units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double v = (double)bytes;
    int u = 0;
    while (v >= 1024.0 && u < 5)
    {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        _snprintf_s(out, cap, _TRUNCATE, "%llu B", bytes);
    else
        _snprintf_s(out, cap, _TRUNCATE, "%.2f %s", v, units[u]);
}

void ntu_add_bytes(cJSON *obj, const char *key, unsigned long long bytes)
{
    char pretty[64];
    char prettyKey[128];
    cJSON_AddNumberToObject(obj, key, (double)bytes);
    ntu_bytes_pretty(bytes, pretty, sizeof(pretty));
    _snprintf_s(prettyKey, sizeof(prettyKey), _TRUNCATE, "%s_pretty", key);
    cJSON_AddStringToObject(obj, prettyKey, pretty);
}

/* ---- errors --------------------------------------------------------------- */
const char *ntu_status_string(NTSTATUS status, char *buf, size_t cap)
{
    if (cap == 0)
        return buf;
    WCHAR wbuf[512];
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        ntdll, (DWORD)status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        wbuf, (DWORD)(sizeof(wbuf) / sizeof(WCHAR)), NULL);
    if (n == 0)
    {
        _snprintf_s(buf, cap, _TRUNCATE, "NTSTATUS 0x%08lX", (unsigned long)status);
        return buf;
    }
    /* trim trailing CR/LF/period/space */
    while (n > 0 && (wbuf[n - 1] == L'\r' || wbuf[n - 1] == L'\n' || wbuf[n - 1] == L'.' || wbuf[n - 1] == L' '))
        wbuf[--n] = 0;
    int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, (int)cap, NULL, NULL);
    if (len <= 0)
        _snprintf_s(buf, cap, _TRUNCATE, "NTSTATUS 0x%08lX", (unsigned long)status);
    return buf;
}

cJSON *ntu_status_error(const char *where, NTSTATUS status)
{
    char msg[560];
    char code[16];
    ntu_status_string(status, msg, sizeof(msg));
    _snprintf_s(code, sizeof(code), _TRUNCATE, "0x%08lX", (unsigned long)status);
    cJSON *o = cJSON_CreateObject();
    char full[700];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "%s failed: %s (NTSTATUS %s)", where ? where : "operation", msg, code);
    cJSON_AddStringToObject(o, "error", full);
    cJSON_AddStringToObject(o, "ntstatus", code);
    if (status == STATUS_ACCESS_DENIED)
        cJSON_AddStringToObject(o, "hint", "Access denied. Run the MCP server elevated (as Administrator), and for protected/PPL processes the System Informer kernel driver (KSystemInformer) is required.");
    return o;
}

cJSON *ntu_win_error(const char *where, DWORD err)
{
    WCHAR wbuf[512];
    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wbuf, (DWORD)(sizeof(wbuf) / sizeof(WCHAR)), NULL);
    char msg[560];
    if (n == 0)
    {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "Win32 error %lu", (unsigned long)err);
    }
    else
    {
        while (n > 0 && (wbuf[n - 1] == L'\r' || wbuf[n - 1] == L'\n' || wbuf[n - 1] == L'.' || wbuf[n - 1] == L' '))
            wbuf[--n] = 0;
        WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, msg, (int)sizeof(msg), NULL, NULL);
    }
    cJSON *o = cJSON_CreateObject();
    char full[700];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "%s failed: %s (error %lu)", where ? where : "operation", msg, (unsigned long)err);
    cJSON_AddStringToObject(o, "error", full);
    cJSON_AddNumberToObject(o, "win32error", (double)err);
    if (err == ERROR_ACCESS_DENIED)
        cJSON_AddStringToObject(o, "hint", "Access denied. Run the MCP server elevated (as Administrator).");
    return o;
}

/* ---- processes / threads -------------------------------------------------- */
HANDLE ntu_open_process(DWORD pid, ACCESS_MASK access, NTSTATUS *status)
{
    HANDLE h = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;
    NTSTATUS st = NtOpenProcess(&h, access, &oa, &cid);
    if (status)
        *status = st;
    return NT_SUCCESS(st) ? h : NULL;
}

HANDLE ntu_open_thread(DWORD tid, ACCESS_MASK access, NTSTATUS *status)
{
    HANDLE h = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = NULL;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
    NTSTATUS st = NtOpenThread(&h, access, &oa, &cid);
    if (status)
        *status = st;
    return NT_SUCCESS(st) ? h : NULL;
}

char *ntu_process_image_path(HANDLE process)
{
    ULONG len = 0;
    NTSTATUS st = NtQueryInformationProcess(process, ProcessImageFileNameWin32, NULL, 0, &len);
    if (len == 0)
        len = 1024;
    PUNICODE_STRING us = (PUNICODE_STRING)malloc(len);
    if (!us)
        return NULL;
    st = NtQueryInformationProcess(process, ProcessImageFileNameWin32, us, len, &len);
    if (!NT_SUCCESS(st))
    {
        free(us);
        return NULL;
    }
    char *out = us->Length ? ntu_w2u(us->Buffer, (int)(us->Length / sizeof(WCHAR))) : NULL;
    free(us);
    return out;
}

char *ntu_process_command_line(HANDLE process)
{
    ULONG len = 0;
    NTSTATUS st = NtQueryInformationProcess(process, ProcessCommandLineInformation, NULL, 0, &len);
    if (len == 0)
        return NULL;
    PUNICODE_STRING us = (PUNICODE_STRING)malloc(len);
    if (!us)
        return NULL;
    st = NtQueryInformationProcess(process, ProcessCommandLineInformation, us, len, &len);
    if (!NT_SUCCESS(st))
    {
        free(us);
        return NULL;
    }
    char *out = us->Length ? ntu_w2u(us->Buffer, (int)(us->Length / sizeof(WCHAR))) : NULL;
    free(us);
    return out;
}

/* ---- SIDs ----------------------------------------------------------------- */
char *ntu_sid_to_string(PSID sid)
{
    if (!sid)
        return NULL;
    UNICODE_STRING s;
    if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&s, sid, TRUE)))
        return NULL;
    char *out = ntu_w2u(s.Buffer, (int)(s.Length / sizeof(WCHAR)));
    RtlFreeUnicodeString(&s);
    return out;
}

char *ntu_sid_account(PSID sid)
{
    if (!sid)
        return NULL;
    WCHAR name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, sid, name, &nameLen, domain, &domainLen, &use))
        return NULL;
    WCHAR combined[600];
    if (domain[0])
        _snwprintf_s(combined, 600, _TRUNCATE, L"%s\\%s", domain, name);
    else
        _snwprintf_s(combined, 600, _TRUNCATE, L"%s", name);
    return ntu_w2u(combined, -1);
}

/* ---- privileges / token --------------------------------------------------- */
int ntu_enable_privilege(PCWSTR privilegeName)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    int ok = 0;
    if (LookupPrivilegeValueW(NULL, privilegeName, &tp.Privileges[0].Luid))
    {
        if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) && GetLastError() == ERROR_SUCCESS)
            ok = 1;
    }
    CloseHandle(token);
    return ok;
}

int ntu_current_is_elevated(void)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return 0;
    TOKEN_ELEVATION elevation;
    DWORD cb = 0;
    int result = 0;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &cb))
        result = elevation.TokenIsElevated ? 1 : 0;
    CloseHandle(token);
    return result;
}

/* ---- generic system-information query ------------------------------------- */
NTSTATUS ntu_query_system(SYSTEM_INFORMATION_CLASS cls, PVOID *buffer, ULONG *length)
{
    ULONG len = 0x4000;
    PVOID buf = malloc(len);
    if (!buf)
        return STATUS_NO_MEMORY;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    for (int i = 0; i < 12; i++)
    {
        ULONG ret = 0;
        st = NtQuerySystemInformation(cls, buf, len, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
        {
            ULONG newLen = (ret > len) ? (ret + 0x4000) : (len * 2);
            PVOID nb = realloc(buf, newLen);
            if (!nb)
            {
                free(buf);
                return STATUS_NO_MEMORY;
            }
            buf = nb;
            len = newLen;
            continue;
        }
        break;
    }
    if (NT_SUCCESS(st))
    {
        *buffer = buf;
        if (length)
            *length = len;
    }
    else
    {
        free(buf);
    }
    return st;
}
