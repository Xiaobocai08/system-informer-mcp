#include "memtools.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- helpers -------------------------------------------------------------- */
static int require_pid(const cJSON *args, DWORD *pid, cJSON **err)
{
    int found = 0;
    unsigned long long v = mcp_arg_u64(args, "pid", 0, &found);
    if (!found)
    {
        *err = mcp_err_hint("Pass the process id as \"pid\".", "Missing required argument: pid");
        return 0;
    }
    *pid = (DWORD)v;
    return 1;
}

static const char *protect_string(DWORD p, char *buf, size_t cap)
{
    const char *base;
    switch (p & 0xFF)
    {
    case PAGE_NOACCESS: base = "NA"; break;
    case PAGE_READONLY: base = "R"; break;
    case PAGE_READWRITE: base = "RW"; break;
    case PAGE_WRITECOPY: base = "WC"; break;
    case PAGE_EXECUTE: base = "X"; break;
    case PAGE_EXECUTE_READ: base = "RX"; break;
    case PAGE_EXECUTE_READWRITE: base = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: base = "WCX"; break;
    default: base = "?"; break;
    }
    _snprintf_s(buf, cap, _TRUNCATE, "%s%s%s%s", base,
        (p & PAGE_GUARD) ? "+G" : "", (p & PAGE_NOCACHE) ? "+NC" : "", (p & PAGE_WRITECOMBINE) ? "+WCOMB" : "");
    return buf;
}

static int protect_from_string(const char *s, DWORD *out)
{
    if (!s) return 0;
    if (_stricmp(s, "NA") == 0 || _stricmp(s, "noaccess") == 0) { *out = PAGE_NOACCESS; return 1; }
    if (_stricmp(s, "R") == 0 || _stricmp(s, "readonly") == 0) { *out = PAGE_READONLY; return 1; }
    if (_stricmp(s, "RW") == 0 || _stricmp(s, "readwrite") == 0) { *out = PAGE_READWRITE; return 1; }
    if (_stricmp(s, "WC") == 0 || _stricmp(s, "writecopy") == 0) { *out = PAGE_WRITECOPY; return 1; }
    if (_stricmp(s, "X") == 0 || _stricmp(s, "execute") == 0) { *out = PAGE_EXECUTE; return 1; }
    if (_stricmp(s, "RX") == 0 || _stricmp(s, "execute_read") == 0) { *out = PAGE_EXECUTE_READ; return 1; }
    if (_stricmp(s, "RWX") == 0 || _stricmp(s, "execute_readwrite") == 0) { *out = PAGE_EXECUTE_READWRITE; return 1; }
    if (_stricmp(s, "WCX") == 0 || _stricmp(s, "execute_writecopy") == 0) { *out = PAGE_EXECUTE_WRITECOPY; return 1; }
    /* allow raw numeric */
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    if (end && end != s && *end == 0) { *out = (DWORD)v; return 1; }
    return 0;
}

static const char *type_string(DWORD t)
{
    switch (t)
    {
    case MEM_IMAGE: return "Image";
    case MEM_MAPPED: return "Mapped";
    case MEM_PRIVATE: return "Private";
    default: return "";
    }
}

static const char *state_string(DWORD s)
{
    switch (s)
    {
    case MEM_COMMIT: return "Commit";
    case MEM_RESERVE: return "Reserve";
    case MEM_FREE: return "Free";
    default: return "?";
    }
}

static void add_hex(cJSON *o, const char *key, ULONG_PTR v)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", (unsigned long long)v);
    cJSON_AddStringToObject(o, key, buf);
}

static char *mapped_file_name(HANDLE process, PVOID base)
{
    UCHAR buf[sizeof(UNICODE_STRING) + 2048 * sizeof(WCHAR)];
    SIZE_T ret = 0;
    if (!NT_SUCCESS(NtQueryVirtualMemory(process, base, MemoryMappedFilenameInformation, buf, sizeof(buf), &ret)))
        return NULL;
    PUNICODE_STRING us = (PUNICODE_STRING)buf;
    if (!us->Length) return NULL;
    return ntu_w2u(us->Buffer, (int)(us->Length / sizeof(WCHAR)));
}

/* ---- process_memory_regions ---------------------------------------------- */
cJSON *tool_process_memory_regions(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int includeFree = mcp_arg_bool(args, "include_free", 0);
    const char *typeFilter = mcp_arg_str(args, "type", NULL);
    int executableOnly = mcp_arg_bool(args, "executable_only", 0);
    unsigned long long limit = mcp_arg_u64(args, "limit", 500, NULL);

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(QUERY|VM_READ)", st); }

    cJSON *arr = cJSON_CreateArray();
    ULONG_PTR addr = 0;
    unsigned long long total = 0, emitted = 0;
    unsigned long long committed = 0, privateCommitted = 0, imageCommitted = 0, mappedCommitted = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;
    while (NT_SUCCESS(NtQueryVirtualMemory(h, (PVOID)addr, MemoryBasicInformation, &mbi, sizeof(mbi), &ret)))
    {
        if (mbi.State == MEM_COMMIT)
        {
            committed += mbi.RegionSize;
            if (mbi.Type == MEM_PRIVATE) privateCommitted += mbi.RegionSize;
            else if (mbi.Type == MEM_IMAGE) imageCommitted += mbi.RegionSize;
            else if (mbi.Type == MEM_MAPPED) mappedCommitted += mbi.RegionSize;
        }
        int include = 1;
        if (mbi.State == MEM_FREE && !includeFree) include = 0;
        if (include && typeFilter && typeFilter[0] && _stricmp(type_string(mbi.Type), typeFilter) != 0) include = 0;
        if (include && executableOnly)
        {
            DWORD p = mbi.Protect & 0xFF;
            if (!(p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY))
                include = 0;
        }
        if (include)
        {
            total++;
            if (!limit || emitted < limit)
            {
                cJSON *o = cJSON_CreateObject();
                add_hex(o, "baseAddress", (ULONG_PTR)mbi.BaseAddress);
                add_hex(o, "allocationBase", (ULONG_PTR)mbi.AllocationBase);
                ntu_add_bytes(o, "size", mbi.RegionSize);
                cJSON_AddStringToObject(o, "state", state_string(mbi.State));
                cJSON_AddStringToObject(o, "type", type_string(mbi.Type));
                char pb[32];
                cJSON_AddStringToObject(o, "protect", protect_string(mbi.Protect, pb, sizeof(pb)));
                cJSON_AddStringToObject(o, "allocationProtect", protect_string(mbi.AllocationProtect, pb, sizeof(pb)));
                if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)
                {
                    char *fn = mapped_file_name(h, mbi.BaseAddress);
                    if (fn) { cJSON_AddStringToObject(o, "mappedFile", fn); free(fn); }
                }
                cJSON_AddItemToArray(arr, o);
                emitted++;
            }
        }
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    NtClose(h);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "pid", pid);
    cJSON_AddNumberToObject(result, "matchingRegions", (double)total);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    ntu_add_bytes(result, "committedTotal", committed);
    ntu_add_bytes(result, "committedPrivate", privateCommitted);
    ntu_add_bytes(result, "committedImage", imageCommitted);
    ntu_add_bytes(result, "committedMapped", mappedCommitted);
    cJSON_AddItemToObject(result, "regions", arr);
    return result;
}

/* ---- process_memory_summary ----------------------------------------------- */
cJSON *tool_process_memory_summary(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess", st); }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "pid", pid);
    VM_COUNTERS_EX2 vm;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessVmCounters, &vm, sizeof(vm), NULL)))
    {
        ntu_add_bytes(o, "workingSet", vm.CountersEx.WorkingSetSize);
        ntu_add_bytes(o, "peakWorkingSet", vm.CountersEx.PeakWorkingSetSize);
        ntu_add_bytes(o, "privateBytes", vm.CountersEx.PrivateUsage);
        ntu_add_bytes(o, "privateWorkingSet", vm.PrivateWorkingSetSize);
        ntu_add_bytes(o, "sharedCommit", vm.SharedCommitUsage);
        ntu_add_bytes(o, "virtualSize", vm.CountersEx.VirtualSize);
        ntu_add_bytes(o, "peakVirtualSize", vm.CountersEx.PeakVirtualSize);
        ntu_add_bytes(o, "pagefileUsage", vm.CountersEx.PagefileUsage);
        ntu_add_bytes(o, "peakPagefileUsage", vm.CountersEx.PeakPagefileUsage);
        ntu_add_bytes(o, "pagedPool", vm.CountersEx.QuotaPagedPoolUsage);
        ntu_add_bytes(o, "nonPagedPool", vm.CountersEx.QuotaNonPagedPoolUsage);
        cJSON_AddNumberToObject(o, "pageFaults", vm.CountersEx.PageFaultCount);
    }
    QUOTA_LIMITS_EX ql;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessQuotaLimits, &ql, sizeof(ql), NULL)))
    {
        ntu_add_bytes(o, "minWorkingSetLimit", ql.MinimumWorkingSetSize);
        ntu_add_bytes(o, "maxWorkingSetLimit", ql.MaximumWorkingSetSize);
    }
    NtClose(h);
    return o;
}

/* ---- read_process_memory -------------------------------------------------- */
static void add_hexdump(cJSON *o, const UCHAR *data, SIZE_T len, ULONG_PTR base)
{
    /* compact hex string */
    char *hex = (char *)malloc(len * 2 + 1);
    if (hex)
    {
        static const char digits[] = "0123456789abcdef";
        for (SIZE_T i = 0; i < len; i++)
        {
            hex[i * 2] = digits[data[i] >> 4];
            hex[i * 2 + 1] = digits[data[i] & 0xF];
        }
        hex[len * 2] = 0;
        cJSON_AddStringToObject(o, "hex", hex);
        free(hex);
    }
    /* classic 16-byte-per-line dump with ASCII gutter */
    cJSON *lines = cJSON_CreateArray();
    for (SIZE_T off = 0; off < len; off += 16)
    {
        char line[128];
        int n = _snprintf_s(line, sizeof(line), _TRUNCATE, "%016llX  ", (unsigned long long)(base + off));
        for (SIZE_T i = 0; i < 16; i++)
        {
            if (off + i < len)
                n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, "%02X ", data[off + i]);
            else
                n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, "   ");
        }
        n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, " ");
        for (SIZE_T i = 0; i < 16 && off + i < len; i++)
        {
            UCHAR c = data[off + i];
            line[n++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
        }
        line[n] = 0;
        cJSON_AddItemToArray(lines, cJSON_CreateString(line));
    }
    cJSON_AddItemToObject(o, "dump", lines);
}

cJSON *tool_read_process_memory(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int found = 0;
    unsigned long long address = mcp_arg_u64(args, "address", 0, &found);
    if (!found) { *isError = 1; return mcp_err_hint("Pass \"address\" as a number or hex string like \"0x7ff6a0001000\".", "Missing required argument: address"); }
    unsigned long long size = mcp_arg_u64(args, "size", 256, NULL);
    if (size == 0) size = 1;
    if (size > 65536) { *isError = 1; return mcp_err_hint("Read in chunks of at most 65536 bytes.", "size %llu exceeds the 64 KiB limit", size); }

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_VM_READ)", st); }
    UCHAR *buf = (UCHAR *)malloc((size_t)size);
    SIZE_T got = 0;
    st = NtReadVirtualMemory(h, (PVOID)(ULONG_PTR)address, buf, (SIZE_T)size, &got);
    NtClose(h);
    if (!NT_SUCCESS(st) && got == 0)
    {
        free(buf);
        *isError = 1;
        cJSON *e = ntu_status_error("NtReadVirtualMemory", st);
        if (st == STATUS_PARTIAL_COPY)
            cJSON_ReplaceItemInObject(e, "hint", cJSON_CreateString("The address is not readable (free/reserved/guard page). Use process_memory_regions to find committed regions."));
        return e;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "pid", pid);
    add_hex(o, "address", (ULONG_PTR)address);
    cJSON_AddNumberToObject(o, "bytesRead", (double)got);
    if (got < size)
        cJSON_AddBoolToObject(o, "partial", 1);
    add_hexdump(o, buf, got, (ULONG_PTR)address);
    free(buf);
    return o;
}

/* ---- write_process_memory ------------------------------------------------- */
static int hex_decode(const char *hex, UCHAR **out, SIZE_T *outLen)
{
    size_t n = 0;
    for (const char *p = hex; *p; p++)
        if (*p != ' ' && *p != '-' && *p != ':') n++;
    if (n == 0 || (n & 1)) return 0;
    UCHAR *buf = (UCHAR *)malloc(n / 2);
    size_t i = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++)
    {
        if (*p == ' ' || *p == '-' || *p == ':') continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else { free(buf); return 0; }
        if (hi < 0) hi = v; else { buf[i++] = (UCHAR)((hi << 4) | v); hi = -1; }
    }
    *out = buf;
    *outLen = i;
    return 1;
}

cJSON *tool_write_process_memory(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int found = 0;
    unsigned long long address = mcp_arg_u64(args, "address", 0, &found);
    if (!found) { *isError = 1; return mcp_err("Missing required argument: address"); }
    const char *hex = mcp_arg_str(args, "data_hex", NULL);
    const char *text = mcp_arg_str(args, "data_text", NULL);
    UCHAR *data = NULL; SIZE_T len = 0;
    if (hex && hex[0])
    {
        if (!hex_decode(hex, &data, &len)) { *isError = 1; return mcp_err_hint("data_hex must be an even number of hex digits, e.g. \"90 90 C3\".", "Invalid data_hex"); }
    }
    else if (text)
    {
        len = strlen(text);
        data = (UCHAR *)malloc(len ? len : 1);
        memcpy(data, text, len);
    }
    else { *isError = 1; return mcp_err_hint("Provide data_hex (hex bytes) or data_text (UTF-8 string, no terminator added).", "Missing data_hex or data_text"); }
    if (pid == GetCurrentProcessId()) { free(data); *isError = 1; return mcp_err("Refusing to write into the server's own memory"); }

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, &st);
    if (!h) { free(data); *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_VM_WRITE)", st); }
    SIZE_T written = 0;
    st = NtWriteVirtualMemory(h, (PVOID)(ULONG_PTR)address, data, len, &written);
    if (!NT_SUCCESS(st) && mcp_arg_bool(args, "force_protection", 0))
    {
        /* temporarily make the page writable */
        PVOID base = (PVOID)(ULONG_PTR)address;
        SIZE_T region = len;
        ULONG old = 0;
        if (NT_SUCCESS(NtProtectVirtualMemory(h, &base, &region, PAGE_EXECUTE_READWRITE, &old)))
        {
            st = NtWriteVirtualMemory(h, (PVOID)(ULONG_PTR)address, data, len, &written);
            ULONG dummy;
            NtProtectVirtualMemory(h, &base, &region, old, &dummy);
        }
    }
    NtClose(h);
    free(data);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtWriteVirtualMemory", st); }
    cJSON *o = mcp_ok("Wrote %llu bytes to pid %lu at 0x%llX", (unsigned long long)written, (unsigned long)pid, address);
    cJSON_AddNumberToObject(o, "bytesWritten", (double)written);
    return o;
}

/* ---- protect_process_memory ----------------------------------------------- */
cJSON *tool_protect_process_memory(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int found = 0;
    unsigned long long address = mcp_arg_u64(args, "address", 0, &found);
    if (!found) { *isError = 1; return mcp_err("Missing required argument: address"); }
    unsigned long long size = mcp_arg_u64(args, "size", 4096, NULL);
    DWORD prot;
    if (!protect_from_string(mcp_arg_str(args, "protection", NULL), &prot))
    {
        *isError = 1;
        return mcp_err_hint("Use NA, R, RW, WC, X, RX, RWX or WCX (or a raw PAGE_* number).", "Missing or invalid 'protection'");
    }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_VM_OPERATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_VM_OPERATION)", st); }
    PVOID base = (PVOID)(ULONG_PTR)address;
    SIZE_T region = (SIZE_T)size;
    ULONG old = 0;
    st = NtProtectVirtualMemory(h, &base, &region, prot, &old);
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtProtectVirtualMemory", st); }
    cJSON *o = mcp_ok("Changed protection of 0x%llX (%llu bytes) in pid %lu", address, (unsigned long long)region, (unsigned long)pid);
    char pb[32];
    cJSON_AddStringToObject(o, "previousProtection", protect_string(old, pb, sizeof(pb)));
    add_hex(o, "affectedBase", (ULONG_PTR)base);
    cJSON_AddNumberToObject(o, "affectedSize", (double)region);
    return o;
}

