#include "memtools.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void add_hex(cJSON *o, const char *key, ULONG_PTR v)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", (unsigned long long)v);
    cJSON_AddStringToObject(o, key, buf);
}

static int readable(DWORD protect)
{
    return (protect & 0xFF) != PAGE_NOACCESS && !(protect & PAGE_GUARD);
}

typedef int (*region_cb)(const UCHAR *data, SIZE_T len, ULONG_PTR base, void *ctx);

/* Iterates committed readable regions in [start,end), calling cb; stops when cb returns 0
 * or maxBytes have been scanned. */
static void walk_readable(HANDLE h, ULONG_PTR start, ULONG_PTR end, SIZE_T maxBytes, region_cb cb, void *ctx)
{
    ULONG_PTR addr = start;
    SIZE_T scanned = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;
    UCHAR *buf = NULL;
    SIZE_T bufCap = 0;
    while (addr < end && NT_SUCCESS(NtQueryVirtualMemory(h, (PVOID)addr, MemoryBasicInformation, &mbi, sizeof(mbi), &ret)))
    {
        ULONG_PTR rbase = (ULONG_PTR)mbi.BaseAddress;
        SIZE_T rsize = mbi.RegionSize;
        if (rbase + rsize > end) rsize = end - rbase;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect) && rsize)
        {
            if (rsize > bufCap)
            {
                free(buf);
                buf = (UCHAR *)malloc(rsize);
                bufCap = buf ? rsize : 0;
            }
            SIZE_T got = 0;
            if (buf && NT_SUCCESS(NtReadVirtualMemory(h, (PVOID)rbase, buf, rsize, &got)) && got)
            {
                scanned += got;
                if (!cb(buf, got, rbase, ctx)) break;
            }
            if (maxBytes && scanned >= maxBytes) break;
        }
        ULONG_PTR next = rbase + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    free(buf);
}

/* ---- search_process_memory ------------------------------------------------ */
typedef struct SearchCtx {
    const UCHAR *pat; SIZE_T patLen; int nocase;
    cJSON *hits; unsigned long long maxHits; unsigned long long count;
} SearchCtx;

static int search_cb(const UCHAR *data, SIZE_T len, ULONG_PTR base, void *vctx)
{
    SearchCtx *c = (SearchCtx *)vctx;
    if (len < c->patLen) return 1;
    for (SIZE_T i = 0; i + c->patLen <= len; i++)
    {
        SIZE_T j;
        for (j = 0; j < c->patLen; j++)
        {
            UCHAR a = data[i + j], b = c->pat[j];
            if (c->nocase) { if (a >= 'A' && a <= 'Z') a += 32; if (b >= 'A' && b <= 'Z') b += 32; }
            if (a != b) break;
        }
        if (j != c->patLen) continue;
        c->count++;
        if ((unsigned long long)cJSON_GetArraySize(c->hits) < c->maxHits)
        {
            cJSON *h = cJSON_CreateObject();
            add_hex(h, "address", base + i);
            SIZE_T s = i > 16 ? i - 16 : 0, e = i + c->patLen + 16; if (e > len) e = len;
            char hex[200]; int n = 0;
            for (SIZE_T k = s; k < e && n < 190; k++) n += _snprintf_s(hex + n, sizeof(hex) - n, _TRUNCATE, "%02X", data[k]);
            cJSON_AddStringToObject(h, "contextHex", hex);
            cJSON_AddItemToArray(c->hits, h);
        }
        i += c->patLen - 1;
    }
    return 1;
}

static int decode_pattern(const cJSON *args, UCHAR **out, SIZE_T *len, int *nocase, cJSON **err)
{
    const char *hex = mcp_arg_str(args, "pattern_hex", NULL);
    const char *text = mcp_arg_str(args, "pattern_text", NULL);
    const char *enc = mcp_arg_str(args, "encoding", "utf8");
    *nocase = mcp_arg_bool(args, "case_insensitive", 0);
    if (hex && hex[0])
    {
        size_t n = 0; for (const char *p = hex; *p; p++) if (*p != ' ') n++;
        if (!n || (n & 1)) { *err = mcp_err_hint("pattern_hex needs an even number of hex digits, e.g. \"4D 5A 90\".", "Invalid pattern_hex"); return 0; }
        UCHAR *b = (UCHAR *)malloc(n / 2); size_t i = 0; int hi = -1;
        for (const char *p = hex; *p; p++)
        {
            if (*p == ' ') continue;
            int v = (*p >= '0' && *p <= '9') ? *p - '0' : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 : (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
            if (v < 0) { free(b); *err = mcp_err("Invalid hex digit in pattern_hex"); return 0; }
            if (hi < 0) hi = v; else { b[i++] = (UCHAR)((hi << 4) | v); hi = -1; }
        }
        *out = b; *len = i; return 1;
    }
    if (text && text[0])
    {
        if (_stricmp(enc, "utf16") == 0)
        {
            PWSTR w = ntu_u2w(text);
            *out = (UCHAR *)w; *len = wcslen(w) * sizeof(WCHAR); return 1;
        }
        *len = strlen(text);
        *out = (UCHAR *)malloc(*len); memcpy(*out, text, *len);
        return 1;
    }
    *err = mcp_err_hint("Provide pattern_hex (bytes) or pattern_text (string; encoding utf8 or utf16).", "Missing pattern");
    return 0;
}

static int require_pid2(const cJSON *args, DWORD *pid, cJSON **err)
{
    int found = 0;
    unsigned long long v = mcp_arg_u64(args, "pid", 0, &found);
    if (!found) { *err = mcp_err_hint("Pass the process id as \"pid\".", "Missing required argument: pid"); return 0; }
    *pid = (DWORD)v;
    return 1;
}

cJSON *tool_search_process_memory(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid2(args, &pid, &err)) { *isError = 1; return err; }
    UCHAR *pat = NULL; SIZE_T patLen = 0; int nocase = 0;
    if (!decode_pattern(args, &pat, &patLen, &nocase, &err)) { *isError = 1; return err; }
    unsigned long long start = mcp_arg_u64(args, "start_address", 0, NULL);
    unsigned long long end = mcp_arg_u64(args, "end_address", (unsigned long long)(ULONG_PTR)-1, NULL);
    unsigned long long maxHits = mcp_arg_u64(args, "max_results", 100, NULL);
    unsigned long long maxBytes = mcp_arg_u64(args, "max_scan_bytes", 2ULL * 1024 * 1024 * 1024, NULL);

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &st);
    if (!h) { free(pat); *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_VM_READ)", st); }

    SearchCtx ctx = { pat, patLen, nocase, cJSON_CreateArray(), maxHits ? maxHits : 1, 0 };
    walk_readable(h, (ULONG_PTR)start, (ULONG_PTR)end, (SIZE_T)maxBytes, search_cb, &ctx);
    NtClose(h);
    free(pat);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "pid", pid);
    cJSON_AddNumberToObject(o, "patternLength", (double)patLen);
    cJSON_AddNumberToObject(o, "totalMatches", (double)ctx.count);
    cJSON_AddNumberToObject(o, "returned", cJSON_GetArraySize(ctx.hits));
    cJSON_AddItemToObject(o, "matches", ctx.hits);
    return o;
}

/* ---- process_memory_strings ----------------------------------------------- */
typedef struct StrCtx {
    SIZE_T minLen; int ascii; int unicode; const char *filter;
    cJSON *out; unsigned long long maxResults; unsigned long long total;
} StrCtx;

static int str_matches_filter(const char *s, const char *filter)
{
    if (!filter || !filter[0]) return 1;
    size_t fl = strlen(filter), sl = strlen(s);
    if (fl > sl) return 0;
    for (size_t i = 0; i + fl <= sl; i++) if (_strnicmp(s + i, filter, fl) == 0) return 1;
    return 0;
}

static void emit_string(StrCtx *c, ULONG_PTR addr, const char *s, const char *kind)
{
    if (!str_matches_filter(s, c->filter)) return;
    c->total++;
    if ((unsigned long long)cJSON_GetArraySize(c->out) >= c->maxResults) return;
    cJSON *o = cJSON_CreateObject();
    add_hex(o, "address", addr);
    cJSON_AddStringToObject(o, "type", kind);
    cJSON_AddStringToObject(o, "value", s);
    cJSON_AddItemToArray(c->out, o);
}

static int strings_cb(const UCHAR *data, SIZE_T len, ULONG_PTR base, void *vctx)
{
    StrCtx *c = (StrCtx *)vctx;
    char buf[1024];
    if (c->ascii)
    {
        SIZE_T run = 0;
        for (SIZE_T i = 0; i <= len; i++)
        {
            int printable = i < len && data[i] >= 0x20 && data[i] < 0x7F;
            if (printable) { if (run < sizeof(buf) - 1) buf[run] = (char)data[i]; run++; continue; }
            if (run >= c->minLen) { buf[run < sizeof(buf) - 1 ? run : sizeof(buf) - 1] = 0; emit_string(c, base + i - run, buf, "ascii"); }
            run = 0;
        }
    }
    if (c->unicode)
    {
        SIZE_T run = 0;
        for (SIZE_T i = 0; i + 1 <= len; i += 2)
        {
            int printable = (i + 1 < len) && data[i] >= 0x20 && data[i] < 0x7F && data[i + 1] == 0;
            if (printable) { if (run < sizeof(buf) - 1) buf[run] = (char)data[i]; run++; continue; }
            if (run >= c->minLen) { buf[run < sizeof(buf) - 1 ? run : sizeof(buf) - 1] = 0; emit_string(c, base + i - run * 2, buf, "unicode"); }
            run = 0;
        }
    }
    return (unsigned long long)cJSON_GetArraySize(c->out) < c->maxResults || c->total < c->maxResults * 50;
}

cJSON *tool_process_memory_strings(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid2(args, &pid, &err)) { *isError = 1; return err; }
    StrCtx ctx;
    ctx.minLen = (SIZE_T)mcp_arg_u64(args, "min_length", 6, NULL);
    if (ctx.minLen < 3) ctx.minLen = 3;
    ctx.ascii = mcp_arg_bool(args, "ascii", 1);
    ctx.unicode = mcp_arg_bool(args, "unicode", 1);
    ctx.filter = mcp_arg_str(args, "filter", NULL);
    ctx.out = cJSON_CreateArray();
    ctx.maxResults = mcp_arg_u64(args, "max_results", 200, NULL);
    if (!ctx.maxResults) ctx.maxResults = 1;
    ctx.total = 0;
    unsigned long long start = mcp_arg_u64(args, "start_address", 0, NULL);
    unsigned long long end = mcp_arg_u64(args, "end_address", (unsigned long long)(ULONG_PTR)-1, NULL);
    unsigned long long maxBytes = mcp_arg_u64(args, "max_scan_bytes", 512ULL * 1024 * 1024, NULL);
    int privateOnly = mcp_arg_bool(args, "private_only", 1);

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &st);
    if (!h) { cJSON_Delete(ctx.out); *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_VM_READ)", st); }

    if (privateOnly)
    {
        /* walk regions ourselves so we can skip image/mapped */
        ULONG_PTR addr = (ULONG_PTR)start; SIZE_T scanned = 0;
        MEMORY_BASIC_INFORMATION mbi; SIZE_T ret; UCHAR *buf = NULL; SIZE_T cap = 0;
        while (addr < (ULONG_PTR)end && NT_SUCCESS(NtQueryVirtualMemory(h, (PVOID)addr, MemoryBasicInformation, &mbi, sizeof(mbi), &ret)))
        {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && readable(mbi.Protect))
            {
                if (mbi.RegionSize > cap) { free(buf); buf = (UCHAR *)malloc(mbi.RegionSize); cap = buf ? mbi.RegionSize : 0; }
                SIZE_T got = 0;
                if (buf && NT_SUCCESS(NtReadVirtualMemory(h, mbi.BaseAddress, buf, mbi.RegionSize, &got)) && got)
                {
                    scanned += got;
                    if (!strings_cb(buf, got, (ULONG_PTR)mbi.BaseAddress, &ctx)) break;
                }
                if (scanned >= (SIZE_T)maxBytes) break;
            }
            ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
        free(buf);
    }
    else
        walk_readable(h, (ULONG_PTR)start, (ULONG_PTR)end, (SIZE_T)maxBytes, strings_cb, &ctx);
    NtClose(h);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "pid", pid);
    cJSON_AddNumberToObject(o, "totalFound", (double)ctx.total);
    cJSON_AddNumberToObject(o, "returned", cJSON_GetArraySize(ctx.out));
    cJSON_AddItemToObject(o, "strings", ctx.out);
    return o;
}

/* ---- registration --------------------------------------------------------- */
#define PID_PROP "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Process id (number or decimal/hex string).\"}"
#define ADDR_PROP "\"address\":{\"type\":[\"integer\",\"string\"],\"description\":\"Virtual address in the target process, e.g. \\\"0x7ff6a0001000\\\".\"}"
#define CONFIRM_PROP "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true. This tool modifies the target process; refused without explicit confirmation.\"}"
#define RANGE_PROPS "\"start_address\":{\"type\":[\"integer\",\"string\"],\"default\":0,\"description\":\"Scan start address.\"},\"end_address\":{\"type\":[\"integer\",\"string\"],\"description\":\"Scan end address (exclusive). Default: whole address space.\"}"

static const Tool g_memory_tools[] = {
    { "process_memory_regions", "Memory regions",
      "The System Informer 'Memory' page: each virtual-memory region of a process with base/allocation address, "
      "size, state (Commit/Reserve/Free), type (Image/Mapped/Private), protection (R/RW/RX/RWX/NA...) and the "
      "mapped file for image/mapped regions, plus committed totals by type. executable_only=true finds RWX/shellcode "
      "regions; type=Private shows heaps. Output is capped by limit.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"type\":{\"type\":\"string\",\"enum\":[\"Image\",\"Mapped\",\"Private\"],\"description\":\"Only regions of this type.\"},"
      "\"executable_only\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Only regions with an execute protection.\"},"
      "\"include_free\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Include free (unallocated) ranges.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":500,\"description\":\"Max regions to return (0 = all).\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_process_memory_regions },

    { "process_memory_summary", "Memory summary",
      "Memory counters for one process: working set (current/peak/private), private bytes, shared commit, virtual "
      "size, pagefile usage, paged/non-paged pool, page faults and working-set limits. Cheap; use before the heavier "
      "process_memory_regions.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_process_memory_summary },
    { "read_process_memory", "Read memory",
      "Read up to 64 KiB of another process's memory (System Informer memory viewer). Returns a hex string and a "
      "16-bytes-per-line dump with ASCII gutter. Find addresses via process_memory_regions, process_modules or "
      "search_process_memory. Unreadable pages give a clear error with a hint.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," ADDR_PROP ","
      "\"size\":{\"type\":\"integer\",\"default\":256,\"description\":\"Bytes to read (1-65536).\"}"
      "},\"required\":[\"pid\",\"address\"],\"additionalProperties\":false}", 0, tool_read_process_memory },
    { "write_process_memory", "Write memory",
      "GUARDED (confirm=true required). Write bytes into another process. Can corrupt or crash the target; use for "
      "patching/unblocking with care. Provide data_hex or data_text; force_protection temporarily makes read-only "
      "pages writable.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," ADDR_PROP ","
      "\"data_hex\":{\"type\":\"string\",\"description\":\"Bytes as hex, e.g. \\\"90 90 C3\\\".\"},"
      "\"data_text\":{\"type\":\"string\",\"description\":\"UTF-8 text to write (no null terminator added).\"},"
      "\"force_protection\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Temporarily set RWX if the initial write fails.\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"address\",\"confirm\"],\"additionalProperties\":false}", 1, tool_write_process_memory },
    { "protect_process_memory", "Change memory protection",
      "GUARDED (confirm=true required). Change the page protection of a range in another process (e.g. make code "
      "writable or a region non-executable). Returns the previous protection.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," ADDR_PROP ","
      "\"size\":{\"type\":\"integer\",\"default\":4096,\"description\":\"Bytes to change (rounded to pages).\"},"
      "\"protection\":{\"type\":\"string\",\"description\":\"NA, R, RW, WC, X, RX, RWX or WCX.\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"address\",\"protection\",\"confirm\"],\"additionalProperties\":false}", 1, tool_protect_process_memory },
    { "search_process_memory", "Search memory",
      "Scan another process's committed memory for a byte pattern or string (System Informer memory search). "
      "Provide pattern_hex (bytes) or pattern_text (encoding utf8/utf16, optional case_insensitive). Returns match "
      "addresses with surrounding context bytes. Bound the scan with start/end address and max_scan_bytes.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"pattern_hex\":{\"type\":\"string\",\"description\":\"Byte pattern as hex, e.g. \\\"48 8B 05\\\".\"},"
      "\"pattern_text\":{\"type\":\"string\",\"description\":\"Text to search for.\"},"
      "\"encoding\":{\"type\":\"string\",\"enum\":[\"utf8\",\"utf16\"],\"default\":\"utf8\"},"
      "\"case_insensitive\":{\"type\":\"boolean\",\"default\":false},"
      "\"max_results\":{\"type\":\"integer\",\"default\":100}," RANGE_PROPS ","
      "\"max_scan_bytes\":{\"type\":\"integer\",\"description\":\"Stop after scanning this many bytes.\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_search_process_memory },
    { "process_memory_strings", "Extract strings",
      "Extract printable ASCII and/or UTF-16 strings from a process's memory (like Sysinternals strings, on a live "
      "process). By default scans only Private regions (heaps/stacks) which is where interesting runtime data lives; "
      "set private_only=false to include images/mapped files. Filter by substring.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"min_length\":{\"type\":\"integer\",\"default\":6},"
      "\"ascii\":{\"type\":\"boolean\",\"default\":true},"
      "\"unicode\":{\"type\":\"boolean\",\"default\":true},"
      "\"private_only\":{\"type\":\"boolean\",\"default\":true},"
      "\"filter\":{\"type\":\"string\",\"description\":\"Only strings containing this substring (case-insensitive).\"},"
      "\"max_results\":{\"type\":\"integer\",\"default\":200}," RANGE_PROPS ","
      "\"max_scan_bytes\":{\"type\":\"integer\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_process_memory_strings },
};

void register_memory_tools(void)
{
    for (size_t i = 0; i < sizeof(g_memory_tools) / sizeof(g_memory_tools[0]); i++)
        mcp_register_tool(&g_memory_tools[i]);
}
