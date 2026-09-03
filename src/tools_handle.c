#include "ntutil.h"
#include "mcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Object names are obtained by duplicating a handle into our process and
 * calling NtQueryObject. For some object types (notably synchronous named
 * pipes whose peer never replies) NtQueryObject blocks forever. System
 * Informer solves this with a worker thread and a timeout; we do the same.
 * A wedged worker is abandoned (never reused) and its handle deliberately
 * leaked rather than closed out from under the blocked call.
 */

typedef struct NameQuery {
    HANDLE handle;          /* duplicated handle in our process */
    HANDLE doneEvent;
    char  *name;            /* result (malloc, UTF-8) or NULL */
    volatile LONG finished;
} NameQuery;

static DWORD WINAPI name_worker(LPVOID param)
{
    NameQuery *q = (NameQuery *)param;
    ULONG len = 0;
    NtQueryObject(q->handle, ObjectNameInformation, NULL, 0, &len);
    if (len)
    {
        POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)malloc(len);
        if (oni)
        {
            if (NT_SUCCESS(NtQueryObject(q->handle, ObjectNameInformation, oni, len, &len)) && oni->Name.Length)
                q->name = ntu_w2u(oni->Name.Buffer, (int)(oni->Name.Length / sizeof(WCHAR)));
            free(oni);
        }
    }
    InterlockedExchange(&q->finished, 1);
    SetEvent(q->doneEvent);
    return 0;
}

/* Returns malloc'd UTF-8 name or NULL. Never blocks longer than timeoutMs.
 * The duplicated handle is closed here on success, leaked on timeout. */
static char *query_object_name(HANDLE dup, DWORD timeoutMs)
{
    NameQuery *q = (NameQuery *)calloc(1, sizeof(NameQuery));
    if (!q) { NtClose(dup); return NULL; }
    q->handle = dup;
    q->doneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!q->doneEvent) { NtClose(dup); free(q); return NULL; }
    HANDLE th = CreateThread(NULL, 0, name_worker, q, 0, NULL);
    if (!th) { CloseHandle(q->doneEvent); NtClose(dup); free(q); return NULL; }

    char *result = NULL;
    if (WaitForSingleObject(q->doneEvent, timeoutMs) == WAIT_OBJECT_0)
    {
        result = q->name;         /* take ownership */
        NtClose(q->handle);
        CloseHandle(q->doneEvent);
        CloseHandle(th);
        free(q);
    }
    else
    {
        /* Worker is wedged inside NtQueryObject. Leak handle + q so it stays
         * valid for the blocked call; just detach. */
        CloseHandle(th);
    }
    return result;
}

/* ---- object type names ---------------------------------------------------- */
/* Map ObjectTypeIndex -> type name via NtQueryObject(ObjectTypesInformation) once. */
static char **g_typeNames;
static ULONG  g_typeCount;

static void load_type_names(void)
{
    if (g_typeNames) return;
    /* The NULL-buffer size probe is unreliable for this class on some builds,
     * so allocate a generous buffer and grow on mismatch. */
    ULONG len = 0x4000;
    POBJECT_TYPES_INFORMATION types = NULL;
    NTSTATUS st = STATUS_INFO_LENGTH_MISMATCH;
    for (int attempt = 0; attempt < 6; attempt++)
    {
        free(types);
        types = (POBJECT_TYPES_INFORMATION)malloc(len);
        if (!types) return;
        ULONG ret = 0;
        st = NtQueryObject(NULL, ObjectTypesInformation, types, len, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
        {
            len = (ret > len) ? ret + 0x1000 : len * 2;
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(st)) { free(types); return; }

    g_typeCount = 1024;
    g_typeNames = (char **)calloc(g_typeCount, sizeof(char *));
    if (!g_typeNames) { free(types); return; }
    POBJECT_TYPE_INFORMATION t = (POBJECT_TYPE_INFORMATION)((PUCHAR)types + ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR));
    for (ULONG i = 0; i < types->NumberOfTypes; i++)
    {
        /* On Win8.1+ TypeIndex holds the real index matching the handle table's
         * ObjectTypeIndex. Older builds report 0, where index == position + 2. */
        ULONG idx = t->TypeIndex ? t->TypeIndex : (i + 2);
        if (idx < g_typeCount && t->TypeName.Length && !g_typeNames[idx])
            g_typeNames[idx] = ntu_w2u(t->TypeName.Buffer, (int)(t->TypeName.Length / sizeof(WCHAR)));
        t = (POBJECT_TYPE_INFORMATION)((PUCHAR)t->TypeName.Buffer + ALIGN_UP(t->TypeName.MaximumLength, ULONG_PTR));
    }
    free(types);
}

static const char *type_name(ULONG index)
{
    if (g_typeNames && index < g_typeCount && g_typeNames[index])
        return g_typeNames[index];
    return NULL;
}

/* ---- enumeration ---------------------------------------------------------- */
static PSYSTEM_HANDLE_INFORMATION_EX query_handles(void)
{
    PVOID buf = NULL; ULONG len = 0;
    if (!NT_SUCCESS(ntu_query_system(SystemExtendedHandleInformation, &buf, &len)))
        return NULL;
    return (PSYSTEM_HANDLE_INFORMATION_EX)buf;
}

static const char *attr_flags(ULONG a, char *buf, size_t cap)
{
    buf[0] = 0;
    if (a & OBJ_INHERIT) strcat_s(buf, cap, "inherit,");
    if (a & OBJ_PROTECT_CLOSE) strcat_s(buf, cap, "protected,");
    size_t l = strlen(buf); if (l) buf[l-1] = 0;
    return buf;
}

/* Duplicate a target process handle into ours (for name/type queries). */
static HANDLE dup_from(HANDLE process, HANDLE remote, ACCESS_MASK access)
{
    HANDLE dup = NULL;
    if (NT_SUCCESS(NtDuplicateObject(process, remote, NtCurrentProcess(), &dup, access, 0, 0)))
        return dup;
    return NULL;
}

/* ---- list_handles --------------------------------------------------------- */
static cJSON *tool_list_handles(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD pid = (DWORD)mcp_arg_u64(args, "pid", 0, &found);
    if (!found) { *isError = 1; return mcp_err_hint("Pass the owning process id as \"pid\".", "Missing required argument: pid"); }
    const char *typeFilter = mcp_arg_str(args, "type", NULL);
    int wantNames = mcp_arg_bool(args, "resolve_names", 1);
    unsigned long long limit = mcp_arg_u64(args, "limit", 500, NULL);
    DWORD timeout = (DWORD)mcp_arg_u64(args, "name_timeout_ms", 100, NULL);

    load_type_names();
    PSYSTEM_HANDLE_INFORMATION_EX all = query_handles();
    if (!all) { *isError = 1; return mcp_err("Could not query system handle table (need elevation?)"); }

    HANDLE proc = NULL;
    if (wantNames)
        proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

    cJSON *arr = cJSON_CreateArray();
    unsigned long long matched = 0, emitted = 0;
    for (ULONG_PTR i = 0; i < all->NumberOfHandles; i++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &all->Handles[i];
        if ((DWORD)(ULONG_PTR)e->UniqueProcessId != pid) continue;
        const char *tn = type_name(e->ObjectTypeIndex);
        if (typeFilter && typeFilter[0] && (!tn || _stricmp(tn, typeFilter) != 0)) continue;
        matched++;
        if (limit && emitted >= limit) continue;

        cJSON *o = cJSON_CreateObject();
        char hv[32]; _snprintf_s(hv, sizeof(hv), _TRUNCATE, "0x%llX", (unsigned long long)(ULONG_PTR)e->HandleValue);
        cJSON_AddStringToObject(o, "handle", hv);
        cJSON_AddStringToObject(o, "type", tn ? tn : "?");
        cJSON_AddNumberToObject(o, "typeIndex", e->ObjectTypeIndex);
        char acc[16]; _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%08lX", (unsigned long)e->GrantedAccess);
        cJSON_AddStringToObject(o, "grantedAccess", acc);
        char obj[32]; _snprintf_s(obj, sizeof(obj), _TRUNCATE, "0x%llX", (unsigned long long)(ULONG_PTR)e->Object);
        cJSON_AddStringToObject(o, "object", obj);
        char fl[64]; cJSON_AddStringToObject(o, "attributes", attr_flags(e->HandleAttributes, fl, sizeof(fl)));
        if (wantNames && proc)
        {
            HANDLE dup = dup_from(proc, e->HandleValue, 0);
            if (dup)
            {
                char *name = query_object_name(dup, timeout);
                if (name) { cJSON_AddStringToObject(o, "name", name); free(name); }
            }
        }
        cJSON_AddItemToArray(arr, o);
        emitted++;
    }
    if (proc) CloseHandle(proc);
    free(all);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "pid", pid);
    cJSON_AddNumberToObject(result, "totalHandles", (double)matched);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    cJSON_AddItemToObject(result, "handles", arr);
    return result;
}

/* ---- handle_type_summary -------------------------------------------------- */
static cJSON *tool_handle_type_summary(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD pid = (DWORD)mcp_arg_u64(args, "pid", 0, &found);
    load_type_names();
    PSYSTEM_HANDLE_INFORMATION_EX all = query_handles();
    if (!all) { *isError = 1; return mcp_err("Could not query system handle table (need elevation?)"); }

    /* count per type index */
    ULONG counts[512] = {0};
    unsigned long long total = 0;
    for (ULONG_PTR i = 0; i < all->NumberOfHandles; i++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &all->Handles[i];
        if (found && (DWORD)(ULONG_PTR)e->UniqueProcessId != pid) continue;
        if (e->ObjectTypeIndex < 512) counts[e->ObjectTypeIndex]++;
        total++;
    }
    free(all);

    cJSON *byType = cJSON_CreateObject();
    for (ULONG i = 0; i < 512; i++)
    {
        if (!counts[i]) continue;
        const char *tn = type_name(i);
        char key[64];
        if (!tn) { _snprintf_s(key, sizeof(key), _TRUNCATE, "type#%lu", i); tn = key; }
        cJSON_AddNumberToObject(byType, tn, counts[i]);
    }
    cJSON *result = cJSON_CreateObject();
    if (found) cJSON_AddNumberToObject(result, "pid", pid);
    cJSON_AddNumberToObject(result, "totalHandles", (double)total);
    cJSON_AddItemToObject(result, "byType", byType);
    return result;
}

/* ---- find_handles_by_name ------------------------------------------------- */
static int name_contains(const char *name, const char *needle)
{
    size_t nl = strlen(needle), sl = strlen(name);
    if (nl > sl) return 0;
    for (size_t i = 0; i + nl <= sl; i++) if (_strnicmp(name + i, needle, nl) == 0) return 1;
    return 0;
}

static cJSON *tool_find_handles_by_name(const cJSON *args, int *isError)
{
    const char *needle = mcp_arg_str(args, "name", NULL);
    if (!needle || !needle[0]) { *isError = 1; return mcp_err_hint("Pass a file/object name substring in \"name\", e.g. a DLL or file path.", "Missing required argument: name"); }
    const char *typeFilter = mcp_arg_str(args, "type", NULL);
    unsigned long long limit = mcp_arg_u64(args, "limit", 100, NULL);
    DWORD timeout = (DWORD)mcp_arg_u64(args, "name_timeout_ms", 50, NULL);

    load_type_names();
    PSYSTEM_HANDLE_INFORMATION_EX all = query_handles();
    if (!all) { *isError = 1; return mcp_err("Could not query system handle table (need elevation?)"); }

    /* cache process handles for duplication, keyed by pid */
    cJSON *arr = cJSON_CreateArray();
    unsigned long long emitted = 0, scanned = 0;
    HANDLE lastProc = NULL; DWORD lastPid = (DWORD)-1;
    for (ULONG_PTR i = 0; i < all->NumberOfHandles && (!limit || emitted < limit); i++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &all->Handles[i];
        const char *tn = type_name(e->ObjectTypeIndex);
        if (typeFilter && typeFilter[0] && (!tn || _stricmp(tn, typeFilter) != 0)) continue;
        /* only bother querying names for types that have them */
        if (!tn) continue;
        if (typeFilter == NULL && !(_stricmp(tn, "File") == 0 || _stricmp(tn, "Key") == 0 ||
            _stricmp(tn, "Section") == 0 || _stricmp(tn, "Event") == 0 || _stricmp(tn, "Mutant") == 0 ||
            _stricmp(tn, "Semaphore") == 0 || _stricmp(tn, "Directory") == 0 || _stricmp(tn, "SymbolicLink") == 0 ||
            _stricmp(tn, "ALPC Port") == 0)) continue;

        DWORD pid = (DWORD)(ULONG_PTR)e->UniqueProcessId;
        if (pid != lastPid) { if (lastProc) CloseHandle(lastProc); lastProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid); lastPid = pid; }
        if (!lastProc) continue;
        HANDLE dup = dup_from(lastProc, e->HandleValue, 0);
        if (!dup) continue;
        char *name = query_object_name(dup, timeout);
        scanned++;
        if (name && name_contains(name, needle))
        {
            cJSON *o = cJSON_CreateObject();
            cJSON_AddNumberToObject(o, "pid", pid);
            char hv[32]; _snprintf_s(hv, sizeof(hv), _TRUNCATE, "0x%llX", (unsigned long long)(ULONG_PTR)e->HandleValue);
            cJSON_AddStringToObject(o, "handle", hv);
            cJSON_AddStringToObject(o, "type", tn);
            cJSON_AddStringToObject(o, "name", name);
            cJSON_AddItemToArray(arr, o);
            emitted++;
        }
        free(name);
    }
    if (lastProc) CloseHandle(lastProc);
    free(all);

    /* enrich with process names */
    cJSON *it;
    cJSON_ArrayForEach(it, arr)
    {
        DWORD pid = (DWORD)cJSON_GetObjectItem(it, "pid")->valuedouble;
        HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, NULL);
        if (h) { char *p = ntu_process_image_path(h); if (p) { cJSON_AddStringToObject(it, "processImage", p); free(p); } NtClose(h); }
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "query", needle);
    cJSON_AddNumberToObject(result, "namedHandlesScanned", (double)scanned);
    cJSON_AddNumberToObject(result, "matches", cJSON_GetArraySize(arr));
    cJSON_AddItemToObject(result, "results", arr);
    return result;
}

/* ---- close_handle --------------------------------------------------------- */
static cJSON *tool_close_handle(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD pid = (DWORD)mcp_arg_u64(args, "pid", 0, &found);
    if (!found) { *isError = 1; return mcp_err("Missing required argument: pid"); }
    int hfound = 0;
    unsigned long long handleValue = mcp_arg_u64(args, "handle", 0, &hfound);
    if (!hfound) { *isError = 1; return mcp_err_hint("Pass the handle value from list_handles as \"handle\".", "Missing required argument: handle"); }

    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) { *isError = 1; return ntu_win_error("OpenProcess(PROCESS_DUP_HANDLE)", GetLastError()); }
    /* Close by duplicating with DUPLICATE_CLOSE_SOURCE. */
    HANDLE dummy = NULL;
    NTSTATUS st = NtDuplicateObject(proc, (HANDLE)(ULONG_PTR)handleValue, NtCurrentProcess(), &dummy,
                                    0, 0, DUPLICATE_CLOSE_SOURCE);
    if (dummy) NtClose(dummy);
    CloseHandle(proc);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)", st); }
    return mcp_ok("Closed handle 0x%llX in pid %lu (the owning process was NOT notified)", handleValue, (unsigned long)pid);
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_handle_tools[] = {
    { "list_handles", "List handles",
      "The System Informer 'Handles' page for one process: every open handle with its type (File, Key, Event, "
      "Section, Process, Thread, ...), handle value, granted access mask, kernel object address, attributes, and "
      "(by default) the resolved object name. Name resolution runs on a worker thread with a timeout so a wedged "
      "named pipe cannot hang the server. Filter by type and cap with limit.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Owning process id.\"},"
      "\"type\":{\"type\":\"string\",\"description\":\"Only handles of this object type, e.g. \\\"File\\\", \\\"Key\\\", \\\"Event\\\".\"},"
      "\"resolve_names\":{\"type\":\"boolean\",\"default\":true,\"description\":\"Resolve object names (slower).\"},"
      "\"name_timeout_ms\":{\"type\":\"integer\",\"default\":100,\"description\":\"Per-handle name-query timeout.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":500}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_list_handles },

    { "handle_type_summary", "Handle type summary",
      "Count of open handles grouped by object type, either for one process (pass pid) or system-wide (omit pid). "
      "Great for spotting handle leaks (e.g. thousands of Event or File handles).",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Limit to this process; omit for system-wide.\"}"
      "},\"additionalProperties\":false}", 0, tool_handle_type_summary },

    { "find_handles_by_name", "Find handles by name",
      "Search every process's named handles for a substring (case-insensitive) to answer 'which process has this "
      "file/DLL/registry key/section open?' - i.e. what is locking a file you cannot delete. Returns owning pid, "
      "process image, handle and full object name. Scans only nameable types by default.",
      "{\"type\":\"object\",\"properties\":{"
      "\"name\":{\"type\":\"string\",\"description\":\"Substring of the object name/path to find, e.g. \\\"MyApp.dll\\\".\"},"
      "\"type\":{\"type\":\"string\",\"description\":\"Restrict to one object type, e.g. \\\"File\\\".\"},"
      "\"name_timeout_ms\":{\"type\":\"integer\",\"default\":50},"
      "\"limit\":{\"type\":\"integer\",\"default\":100}"
      "},\"required\":[\"name\"],\"additionalProperties\":false}", 0, tool_find_handles_by_name },

    { "close_handle", "Close a handle",
      "GUARDED (confirm=true required). Force-close a handle owned by another process (System Informer 'Close "
      "handle'). Dangerous: the owning process is NOT told its handle vanished and may crash or misbehave on next "
      "use. Mainly used to release a lock on a file. Get pid+handle from list_handles or find_handles_by_name.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Owning process id.\"},"
      "\"handle\":{\"type\":[\"integer\",\"string\"],\"description\":\"Handle value (hex string like \\\"0x1a4\\\" from list_handles).\"},"
      "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true.\"}"
      "},\"required\":[\"pid\",\"handle\",\"confirm\"],\"additionalProperties\":false}", 1, tool_close_handle },
};

void register_handle_tools(void)
{
    for (size_t i = 0; i < sizeof(g_handle_tools) / sizeof(g_handle_tools[0]); i++)
        mcp_register_tool(&g_handle_tools[i]);
}
