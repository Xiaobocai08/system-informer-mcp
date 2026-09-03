#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <shlwapi.h>

/* Enumerate a process's loaded modules by walking the PEB Ldr list via
 * ReadProcessMemory. Works for same-bitness targets; for WOW64 targets we read
 * the 64-bit view (native modules), which is what analysts usually want. */

static void add_hex(cJSON *o, const char *key, ULONG_PTR v)
{
    char b[32]; _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%llX", (unsigned long long)v);
    cJSON_AddStringToObject(o, key, b);
}

static cJSON *tool_process_modules(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD pid = (DWORD)mcp_arg_u64(args, "pid", 0, &found);
    if (!found) { *isError = 1; return mcp_err_hint("Pass the process id as \"pid\".", "Missing required argument: pid"); }
    const char *filter = mcp_arg_str(args, "name_filter", NULL);
    unsigned long long limit = mcp_arg_u64(args, "limit", 0, NULL);

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(QUERY|VM_READ)", st); }

    PROCESS_BASIC_INFORMATION pbi;
    st = NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress) { NtClose(h); *isError = 1; return ntu_status_error("query PEB", st); }

    PEB peb; SIZE_T rd;
    if (!NT_SUCCESS(NtReadVirtualMemory(h, pbi.PebBaseAddress, &peb, sizeof(peb), &rd)) || !peb.Ldr)
    { NtClose(h); *isError = 1; return mcp_err("Could not read PEB/Ldr"); }

    PEB_LDR_DATA ldr;
    if (!NT_SUCCESS(NtReadVirtualMemory(h, peb.Ldr, &ldr, sizeof(ldr), &rd)))
    { NtClose(h); *isError = 1; return mcp_err("Could not read PEB_LDR_DATA"); }

    cJSON *arr = cJSON_CreateArray();
    PVOID head = (PVOID)((PUCHAR)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID cur = ldr.InLoadOrderModuleList.Flink;
    unsigned long total = 0, emitted = 0;
    for (int i = 0; i < 4096 && cur && cur != head; i++)
    {
        LDR_DATA_TABLE_ENTRY e;
        if (!NT_SUCCESS(NtReadVirtualMemory(h, CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), &e, sizeof(e), &rd)))
            break;
        cur = e.InLoadOrderLinks.Flink;
        if (!e.DllBase) continue;
        total++;

        char *full = NULL, *base = NULL;
        if (e.FullDllName.Length && e.FullDllName.Length < 0x1000)
        {
            PWSTR w = (PWSTR)malloc(e.FullDllName.Length + sizeof(WCHAR));
            if (w && NT_SUCCESS(NtReadVirtualMemory(h, e.FullDllName.Buffer, w, e.FullDllName.Length, &rd)))
                full = ntu_w2u(w, (int)(e.FullDllName.Length / sizeof(WCHAR)));
            free(w);
        }
        if (e.BaseDllName.Length && e.BaseDllName.Length < 0x1000)
        {
            PWSTR w = (PWSTR)malloc(e.BaseDllName.Length + sizeof(WCHAR));
            if (w && NT_SUCCESS(NtReadVirtualMemory(h, e.BaseDllName.Buffer, w, e.BaseDllName.Length, &rd)))
                base = ntu_w2u(w, (int)(e.BaseDllName.Length / sizeof(WCHAR)));
            free(w);
        }
        if (filter && filter[0] && (!base || !StrStrIA(base, filter))) { free(full); free(base); continue; }
        if (limit && emitted >= limit) { free(full); free(base); continue; }

        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", base ? base : "?");
        if (full) cJSON_AddStringToObject(o, "path", full);
        add_hex(o, "baseAddress", (ULONG_PTR)e.DllBase);
        ntu_add_bytes(o, "size", e.SizeOfImage);
        add_hex(o, "entryPoint", (ULONG_PTR)e.EntryPoint);
        cJSON_AddItemToArray(arr, o);
        emitted++;
        free(full); free(base);
    }
    NtClose(h);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "pid", pid);
    cJSON_AddNumberToObject(result, "moduleCount", (double)total);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    cJSON_AddItemToObject(result, "modules", arr);
    return result;
}

/* ---- list_drivers (kernel modules) ---------------------------------------- */
static cJSON *tool_list_drivers(const cJSON *args, int *isError)
{
    const char *filter = mcp_arg_str(args, "name_filter", NULL);
    PVOID buf = NULL; ULONG len = 0;
    NTSTATUS st = ntu_query_system(SystemModuleInformation, &buf, &len);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("SystemModuleInformation", st); }
    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buf;
    cJSON *arr = cJSON_CreateArray();
    unsigned long emitted = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++)
    {
        PRTL_PROCESS_MODULE_INFORMATION m = &mods->Modules[i];
        const char *name = (const char *)m->FullPathName + m->OffsetToFileName;
        if (filter && filter[0] && !StrStrIA(name, filter)) continue;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", name);
        cJSON_AddStringToObject(o, "path", (const char *)m->FullPathName);
        add_hex(o, "baseAddress", (ULONG_PTR)m->ImageBase);
        ntu_add_bytes(o, "size", m->ImageSize);
        cJSON_AddNumberToObject(o, "loadOrderIndex", m->LoadOrderIndex);
        cJSON_AddItemToArray(arr, o);
        emitted++;
    }
    free(buf);
    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "driverCount", (double)mods->NumberOfModules);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    cJSON_AddItemToObject(result, "drivers", arr);
    return result;
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_module_tools[] = {
    { "process_modules", "List modules (DLLs)",
      "The System Informer 'Modules' page: every module (EXE + DLLs) loaded in a process, with base name, full "
      "path, base address, image size and entry point, obtained by walking the target's PEB loader list. Use to "
      "see what DLLs a process loaded and from where (spotting DLLs in odd locations is a malware signal). "
      "name_filter narrows by substring.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Process id.\"},"
      "\"name_filter\":{\"type\":\"string\",\"description\":\"Case-insensitive substring of the module name.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":0,\"description\":\"Max modules (0 = all).\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_process_modules },

    { "list_drivers", "List kernel drivers",
      "Every loaded kernel module / driver (System Informer 'Drivers'), with name, full path, base address and "
      "size. Kernel base addresses are only visible when the server runs elevated. Use to inventory drivers or "
      "spot an unexpected/unsigned one (pair with verify_file_signature on the path).",
      "{\"type\":\"object\",\"properties\":{"
      "\"name_filter\":{\"type\":\"string\",\"description\":\"Case-insensitive substring of the driver name.\"}"
      "},\"additionalProperties\":false}", 0, tool_list_drivers },
};

void register_module_tools(void)
{
    for (size_t i = 0; i < sizeof(g_module_tools) / sizeof(g_module_tools[0]); i++)
        mcp_register_tool(&g_module_tools[i]);
}
