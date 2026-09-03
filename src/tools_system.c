#include "ntutil.h"
#include "mcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- helpers -------------------------------------------------------------- */
static void add_os_version(cJSON *o)
{
    RTL_OSVERSIONINFOEXW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&vi)))
    {
        char ver[64];
        _snprintf_s(ver, sizeof(ver), _TRUNCATE, "%lu.%lu.%lu",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        cJSON_AddStringToObject(o, "osVersion", ver);
        cJSON_AddNumberToObject(o, "osBuild", vi.dwBuildNumber);
    }
}

static int si_install_path(char *out, size_t cap)
{
    /* env override first */
    DWORD n = GetEnvironmentVariableA("SYSTEMINFORMER_PATH", out, (DWORD)cap);
    if (n > 0 && n < cap)
        return 1;
    const char *candidates[] = {
        "C:\\Program Files\\SystemInformer\\SystemInformer.exe",
        "C:\\Program Files (x86)\\SystemInformer\\SystemInformer.exe",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
    {
        if (GetFileAttributesA(candidates[i]) != INVALID_FILE_ATTRIBUTES)
        {
            _snprintf_s(out, cap, _TRUNCATE, "%s", candidates[i]);
            return 1;
        }
    }
    return 0;
}

static int driver_service_present(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return 0;
    int present = 0;
    /* modern driver service is "KSystemInformer"; older builds used "KProcessHacker3" */
    SC_HANDLE svc = OpenServiceW(scm, L"KSystemInformer", SERVICE_QUERY_STATUS);
    if (!svc)
        svc = OpenServiceW(scm, L"KProcessHacker3", SERVICE_QUERY_STATUS);
    if (svc)
    {
        present = 1;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return present;
}

/* ---- server_status -------------------------------------------------------- */
static cJSON *tool_server_status(const cJSON *args, int *isError)
{
    (void)args; (void)isError;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "server", SIMCP_SERVER_NAME);
    cJSON_AddStringToObject(o, "version", SIMCP_SERVER_VERSION);
    cJSON_AddBoolToObject(o, "elevated", ntu_current_is_elevated());
    add_os_version(o);

    SYSTEM_BASIC_INFORMATION basic;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL)))
        cJSON_AddNumberToObject(o, "processorCount", basic.NumberOfProcessors);

    char path[MAX_PATH];
    int installed = si_install_path(path, sizeof(path));
    cJSON_AddBoolToObject(o, "systemInformerInstalled", installed);
    if (installed)
        cJSON_AddStringToObject(o, "systemInformerPath", path);
    cJSON_AddBoolToObject(o, "kernelDriverPresent", driver_service_present());

    const char *coverage;
    if (ntu_current_is_elevated())
        coverage = "Elevated: full coverage of processes, services, kernel addresses. Protected/PPL processes still need the KSystemInformer driver.";
    else
        coverage = "Not elevated: your own processes are fully visible; other users' processes and kernel addresses are limited. Restart the server as Administrator for full coverage.";
    cJSON_AddStringToObject(o, "coverage", coverage);
    return o;
}

/* ---- system_overview ------------------------------------------------------ */
static cJSON *tool_system_overview(const cJSON *args, int *isError)
{
    (void)args; (void)isError;
    cJSON *o = cJSON_CreateObject();
    add_os_version(o);

    /* machine name */
    {
        WCHAR name[256];
        DWORD len = 256;
        if (GetComputerNameW(name, &len))
            ntu_add_wn(o, "computerName", name, (int)len);
    }

    SYSTEM_BASIC_INFORMATION basic;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL)))
    {
        cJSON_AddNumberToObject(o, "processorCount", basic.NumberOfProcessors);
        cJSON_AddNumberToObject(o, "pageSize", basic.PageSize);
        ntu_add_bytes(o, "physicalMemoryTotal", (unsigned long long)basic.NumberOfPhysicalPages * basic.PageSize);
    }

    /* memory load */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
    {
        cJSON_AddNumberToObject(o, "memoryLoadPercent", ms.dwMemoryLoad);
        ntu_add_bytes(o, "physicalMemoryAvailable", ms.ullAvailPhys);
        ntu_add_bytes(o, "commitTotal", ms.ullTotalPageFile);
        ntu_add_bytes(o, "commitAvailable", ms.ullAvailPageFile);
    }

    /* process / thread / handle totals + uptime */
    SYSTEM_TIMEOFDAY_INFORMATION tod;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemTimeOfDayInformation, &tod, sizeof(tod), NULL)))
    {
        char boot[32];
        ntu_time_to_iso(tod.BootTime.QuadPart, boot, sizeof(boot));
        cJSON_AddStringToObject(o, "bootTime", boot);
        LONG64 upt = (tod.CurrentTime.QuadPart - tod.BootTime.QuadPart) / 10000000LL;
        cJSON_AddNumberToObject(o, "uptimeSeconds", (double)upt);
    }

    /* process / thread / handle totals from the process list */
    {
        PVOID buf = NULL;
        if (NT_SUCCESS(ntu_query_system(SystemProcessInformation, &buf, NULL)))
        {
            ULONG processes = 0, threads = 0, handles = 0;
            PSYSTEM_PROCESS_INFORMATION p = (PSYSTEM_PROCESS_INFORMATION)buf;
            for (;;)
            {
                processes++;
                threads += p->NumberOfThreads;
                handles += p->HandleCount;
                if (p->NextEntryOffset == 0)
                    break;
                p = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)p + p->NextEntryOffset);
            }
            cJSON_AddNumberToObject(o, "processCount", processes);
            cJSON_AddNumberToObject(o, "threadCount", threads);
            cJSON_AddNumberToObject(o, "handleCount", handles);
            free(buf);
        }
    }

    SYSTEM_PERFORMANCE_INFORMATION perf;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemPerformanceInformation, &perf, sizeof(perf), NULL)))
    {
        cJSON_AddNumberToObject(o, "contextSwitches", perf.ContextSwitches);
        cJSON_AddNumberToObject(o, "systemCalls", perf.SystemCalls);
        cJSON_AddNumberToObject(o, "pageFaultCount", perf.PageFaultCount);
    }
    return o;
}

/* ---- system_cpu_usage ----------------------------------------------------- */
static cJSON *tool_system_cpu_usage(const cJSON *args, int *isError)
{
    int perCpu = mcp_arg_bool(args, "per_cpu", 0);
    unsigned long long sampleMs = mcp_arg_u64(args, "sample_ms", 250, NULL);
    if (sampleMs < 50) sampleMs = 50;
    if (sampleMs > 5000) sampleMs = 5000;

    SYSTEM_BASIC_INFORMATION basic;
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL)))
    {
        *isError = 1;
        return mcp_err("Could not query SystemBasicInformation");
    }
    ULONG n = basic.NumberOfProcessors;
    if (n == 0 || n > 512) n = (n == 0) ? 1 : 512;

    size_t bytes = sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * n;
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *a = malloc(bytes);
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *b = malloc(bytes);
    if (!a || !b)
    {
        free(a); free(b);
        *isError = 1;
        return mcp_err("Out of memory");
    }

    NTSTATUS s1 = NtQuerySystemInformation(SystemProcessorPerformanceInformation, a, (ULONG)bytes, NULL);
    Sleep((DWORD)sampleMs);
    NTSTATUS s2 = NtQuerySystemInformation(SystemProcessorPerformanceInformation, b, (ULONG)bytes, NULL);
    if (!NT_SUCCESS(s1) || !NT_SUCCESS(s2))
    {
        free(a); free(b);
        *isError = 1;
        return ntu_status_error("SystemProcessorPerformanceInformation", NT_SUCCESS(s1) ? s2 : s1);
    }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sampleMs", (double)sampleMs);
    cJSON_AddNumberToObject(o, "processorCount", n);

    double totalBusy = 0, totalAll = 0;
    cJSON *arr = perCpu ? cJSON_CreateArray() : NULL;
    for (ULONG i = 0; i < n; i++)
    {
        double idle = (double)(b[i].IdleTime.QuadPart - a[i].IdleTime.QuadPart);
        double kern = (double)(b[i].KernelTime.QuadPart - a[i].KernelTime.QuadPart);
        double user = (double)(b[i].UserTime.QuadPart - a[i].UserTime.QuadPart);
        double all = kern + user;          /* kernel time already includes idle */
        double busy = all - idle;
        double pct = all > 0 ? (busy / all) * 100.0 : 0.0;
        totalBusy += busy;
        totalAll += all;
        if (arr)
        {
            cJSON *c = cJSON_CreateObject();
            cJSON_AddNumberToObject(c, "cpu", i);
            cJSON_AddNumberToObject(c, "usagePercent", (double)((int)(pct * 10 + 0.5)) / 10.0);
            cJSON_AddItemToArray(arr, c);
        }
    }
    double totalPct = totalAll > 0 ? (totalBusy / totalAll) * 100.0 : 0.0;
    cJSON_AddNumberToObject(o, "totalUsagePercent", (double)((int)(totalPct * 10 + 0.5)) / 10.0);
    if (arr)
        cJSON_AddItemToObject(o, "perCpu", arr);

    free(a); free(b);
    return o;
}

/* ---- system_memory -------------------------------------------------------- */
static cJSON *tool_system_memory(const cJSON *args, int *isError)
{
    (void)args; (void)isError;
    cJSON *o = cJSON_CreateObject();
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
    {
        cJSON_AddNumberToObject(o, "memoryLoadPercent", ms.dwMemoryLoad);
        ntu_add_bytes(o, "physicalTotal", ms.ullTotalPhys);
        ntu_add_bytes(o, "physicalAvailable", ms.ullAvailPhys);
        ntu_add_bytes(o, "physicalUsed", ms.ullTotalPhys - ms.ullAvailPhys);
        ntu_add_bytes(o, "pageFileTotal", ms.ullTotalPageFile);
        ntu_add_bytes(o, "pageFileAvailable", ms.ullAvailPageFile);
        ntu_add_bytes(o, "virtualTotal", ms.ullTotalVirtual);
        ntu_add_bytes(o, "virtualAvailable", ms.ullAvailVirtual);
    }
    SYSTEM_BASIC_INFORMATION basic;
    SYSTEM_PERFORMANCE_INFORMATION perf;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL)) &&
        NT_SUCCESS(NtQuerySystemInformation(SystemPerformanceInformation, &perf, sizeof(perf), NULL)))
    {
        ULONG ps = basic.PageSize;
        ntu_add_bytes(o, "committed", (unsigned long long)perf.CommittedPages * ps);
        ntu_add_bytes(o, "commitLimit", (unsigned long long)perf.CommitLimit * ps);
        ntu_add_bytes(o, "pagedPool", (unsigned long long)perf.PagedPoolPages * ps);
        ntu_add_bytes(o, "nonPagedPool", (unsigned long long)perf.NonPagedPoolPages * ps);
    }
    return o;
}

/* ---- system_uptime -------------------------------------------------------- */
static cJSON *tool_system_uptime(const cJSON *args, int *isError)
{
    (void)args;
    SYSTEM_TIMEOFDAY_INFORMATION tod;
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemTimeOfDayInformation, &tod, sizeof(tod), NULL)))
    {
        *isError = 1;
        return mcp_err("Could not query SystemTimeOfDayInformation");
    }
    cJSON *o = cJSON_CreateObject();
    char boot[32], now[32];
    ntu_time_to_iso(tod.BootTime.QuadPart, boot, sizeof(boot));
    ntu_time_to_iso(tod.CurrentTime.QuadPart, now, sizeof(now));
    LONG64 secs = (tod.CurrentTime.QuadPart - tod.BootTime.QuadPart) / 10000000LL;
    cJSON_AddStringToObject(o, "bootTime", boot);
    cJSON_AddStringToObject(o, "currentTime", now);
    cJSON_AddNumberToObject(o, "uptimeSeconds", (double)secs);
    char pretty[64];
    _snprintf_s(pretty, sizeof(pretty), _TRUNCATE, "%lldd %lldh %lldm %llds",
        secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    cJSON_AddStringToObject(o, "uptimePretty", pretty);
    return o;
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_system_tools[] = {
    { "server_status", "Server status",
      "Report this MCP server's version, whether it is running elevated, the OS version, "
      "processor count, and whether the System Informer application and its kernel driver "
      "(KSystemInformer) are present. CALL THIS FIRST in a session to understand your "
      "coverage: many tools return more (or any) data only when the server runs elevated.",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", 0, tool_server_status },

    { "system_overview", "System overview",
      "A one-shot snapshot of the machine: OS version/build, computer name, processor "
      "count, total/available physical memory, commit charge, memory load %, boot time, "
      "uptime, and total process/thread/handle counts. Good starting point for 'how is "
      "this machine doing?'.",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", 0, tool_system_overview },

    { "system_cpu_usage", "CPU usage",
      "Measure current CPU utilisation by sampling processor performance counters twice "
      "over a short interval. Returns total utilisation %, and optionally per-logical-CPU "
      "breakdown. Use this to answer 'how busy is the CPU right now?' (for per-process CPU "
      "use list_processes sorted by cpu).",
      "{\"type\":\"object\",\"properties\":{"
      "\"per_cpu\":{\"type\":\"boolean\",\"description\":\"Include a per-logical-processor breakdown.\",\"default\":false},"
      "\"sample_ms\":{\"type\":\"integer\",\"description\":\"Sampling interval in milliseconds (50-5000).\",\"default\":250}"
      "},\"additionalProperties\":false}", 0, tool_system_cpu_usage },

    { "system_memory", "Memory details",
      "Detailed physical/virtual/commit memory statistics and paged/non-paged pool usage. "
      "Use for memory-pressure questions.",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", 0, tool_system_memory },

    { "system_uptime", "Uptime",
      "Boot time, current system time, and uptime (seconds and human-readable).",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", 0, tool_system_uptime },
};

void register_system_tools(void)
{
    for (size_t i = 0; i < sizeof(g_system_tools) / sizeof(g_system_tools[0]); i++)
        mcp_register_tool(&g_system_tools[i]);
}
