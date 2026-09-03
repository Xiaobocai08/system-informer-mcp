#include "procsnap.h"
#include "mcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- helpers -------------------------------------------------------------- */
static int require_tid(const cJSON *args, DWORD *tid, cJSON **err)
{
    int found = 0;
    unsigned long long v = mcp_arg_u64(args, "tid", 0, &found);
    if (!found)
    {
        *err = mcp_err_hint("Pass the thread id as \"tid\". Use process_threads to list a process's threads.", "Missing required argument: tid");
        return 0;
    }
    *tid = (DWORD)v;
    return 1;
}

static void add_hex_ptr(cJSON *o, const char *key, PVOID p)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", (unsigned long long)(ULONG_PTR)p);
    cJSON_AddStringToObject(o, key, buf);
}

/* Resolve address -> "module.dll+0x1234" using the owning process's module list. */
static void add_symbolic_address(cJSON *o, const char *key, HANDLE process, PVOID addr)
{
    if (!addr || !process)
        return;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret = 0;
    if (!NT_SUCCESS(NtQueryVirtualMemory(process, addr, MemoryBasicInformation, &mbi, sizeof(mbi), &ret)))
        return;
    if (mbi.Type != MEM_IMAGE)
        return;
    /* Mapped file name of the allocation base */
    UCHAR buf[sizeof(UNICODE_STRING) + 1024 * sizeof(WCHAR)];
    if (NT_SUCCESS(NtQueryVirtualMemory(process, mbi.AllocationBase, MemoryMappedFilenameInformation, buf, sizeof(buf), &ret)))
    {
        PUNICODE_STRING us = (PUNICODE_STRING)buf;
        /* take just the file name */
        PWSTR name = us->Buffer;
        for (PWSTR p = us->Buffer; p < us->Buffer + us->Length / sizeof(WCHAR); p++)
            if (*p == L'\\') name = p + 1;
        int nameLen = (int)((us->Buffer + us->Length / sizeof(WCHAR)) - name);
        char *u = ntu_w2u(name, nameLen);
        if (u)
        {
            char sym[600];
            _snprintf_s(sym, sizeof(sym), _TRUNCATE, "%s+0x%llX", u, (unsigned long long)((ULONG_PTR)addr - (ULONG_PTR)mbi.AllocationBase));
            cJSON_AddStringToObject(o, key, sym);
            free(u);
        }
    }
}

/* Per-thread detail fields needing a thread handle. */
static void add_thread_handle_fields(cJSON *o, DWORD tid, HANDLE process)
{
    NTSTATUS st;
    HANDLE h = ntu_open_thread(tid, THREAD_QUERY_LIMITED_INFORMATION, &st);
    if (!h)
        return;

    PVOID start = NULL;
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadQuerySetWin32StartAddress, &start, sizeof(start), NULL)) && start)
    {
        add_hex_ptr(o, "startAddress", start);
        add_symbolic_address(o, "startAddressSymbolic", process, start);
    }

    ULONG v = 0;
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadSuspendCount, &v, sizeof(v), NULL)))
        cJSON_AddNumberToObject(o, "suspendCount", v);
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadIsIoPending, &v, sizeof(v), NULL)))
        cJSON_AddBoolToObject(o, "ioPending", v ? 1 : 0);
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadPriorityBoost, &v, sizeof(v), NULL)))
        cJSON_AddBoolToObject(o, "priorityBoostDisabled", v ? 1 : 0);

    THREAD_CYCLE_TIME_INFORMATION cyc;
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadCycleTime, &cyc, sizeof(cyc), NULL)))
        cJSON_AddNumberToObject(o, "cycleTime", (double)cyc.AccumulatedCycles);

    /* thread name (Win10+) */
    UCHAR nbuf[sizeof(THREAD_NAME_INFORMATION) + 512 * sizeof(WCHAR)];
    ULONG nlen = 0;
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadNameInformation, nbuf, sizeof(nbuf), &nlen)))
    {
        PTHREAD_NAME_INFORMATION tn = (PTHREAD_NAME_INFORMATION)nbuf;
        if (tn->ThreadName.Length)
            ntu_add_us(o, "threadName", &tn->ThreadName);
    }

    THREAD_BASIC_INFORMATION tbi;
    if (NT_SUCCESS(NtQueryInformationThread(h, ThreadBasicInformation, &tbi, sizeof(tbi), NULL)))
    {
        add_hex_ptr(o, "tebAddress", tbi.TebBaseAddress);
        cJSON_AddNumberToObject(o, "affinityMask", (double)tbi.AffinityMask);
        cJSON_AddBoolToObject(o, "running", tbi.ExitStatus == STATUS_PENDING ? 1 : 0);
    }

    NtClose(h);
}

static void add_thread_snapshot_fields(cJSON *o, PSYSTEM_THREAD_INFORMATION t)
{
    cJSON_AddNumberToObject(o, "tid", (double)(ULONG_PTR)t->ClientId.UniqueThread);
    cJSON_AddNumberToObject(o, "pid", (double)(ULONG_PTR)t->ClientId.UniqueProcess);
    cJSON_AddStringToObject(o, "state", thread_state_name(t->ThreadState));
    if (t->ThreadState == Waiting)
        cJSON_AddStringToObject(o, "waitReason", wait_reason_name(t->WaitReason));
    cJSON_AddNumberToObject(o, "priority", t->Priority);
    cJSON_AddNumberToObject(o, "basePriority", t->BasePriority);
    cJSON_AddNumberToObject(o, "contextSwitches", t->ContextSwitches);
    cJSON_AddNumberToObject(o, "userTimeMs", (double)(t->UserTime.QuadPart / 10000));
    cJSON_AddNumberToObject(o, "kernelTimeMs", (double)(t->KernelTime.QuadPart / 10000));
    char ts[32];
    ntu_time_to_iso(t->CreateTime.QuadPart, ts, sizeof(ts));
    cJSON_AddStringToObject(o, "createTime", ts);
    add_hex_ptr(o, "startAddressKernel", t->StartAddress);
}

/* ---- process_threads ------------------------------------------------------ */
typedef struct TRow { PSYSTEM_THREAD_INFORMATION t; LONG64 cpuDelta; } TRow;
static int cmp_trows_cpu(const void *a, const void *b)
{
    const TRow *x = (const TRow *)a, *y = (const TRow *)b;
    return (x->cpuDelta < y->cpuDelta) - (x->cpuDelta > y->cpuDelta);
}

static cJSON *tool_process_threads(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD pid = (DWORD)mcp_arg_u64(args, "pid", 0, &found);
    if (!found)
    {
        *isError = 1;
        return mcp_err_hint("Pass the owning process id as \"pid\".", "Missing required argument: pid");
    }
    int detailed = mcp_arg_bool(args, "detailed", 1);
    unsigned long long limit = mcp_arg_u64(args, "limit", 0, NULL);
    const char *sortBy = mcp_arg_str(args, "sort_by", "cpu");
    unsigned long long sampleMs = mcp_arg_u64(args, "sample_ms", 300, NULL);
    if (sampleMs < 50) sampleMs = 50;
    if (sampleMs > 5000) sampleMs = 5000;

    ProcSnap s1 = {0}, s2 = {0};
    NTSTATUS st = snap_take(&s1);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("SystemProcessInformation", st); }
    int wantCpu = strcmp(sortBy, "cpu") == 0;
    if (wantCpu)
    {
        Sleep((DWORD)sampleMs);
        st = snap_take(&s2);
        if (!NT_SUCCESS(st)) { snap_free(&s1); *isError = 1; return ntu_status_error("SystemProcessInformation", st); }
    }
    ProcSnap *cur = wantCpu ? &s2 : &s1;
    PSYSTEM_PROCESS_INFORMATION p = snap_find(cur, pid);
    if (!p)
    {
        snap_free(&s1); if (wantCpu) snap_free(&s2);
        *isError = 1;
        return mcp_err("No process with pid %lu", (unsigned long)pid);
    }
    PSYSTEM_PROCESS_INFORMATION prev = wantCpu ? snap_find(&s1, pid) : NULL;

    TRow *rows = (TRow *)calloc(p->NumberOfThreads ? p->NumberOfThreads : 1, sizeof(TRow));
    for (ULONG i = 0; i < p->NumberOfThreads; i++)
    {
        rows[i].t = &p->Threads[i];
        rows[i].cpuDelta = 0;
        if (prev)
        {
            for (ULONG j = 0; j < prev->NumberOfThreads; j++)
            {
                if (prev->Threads[j].ClientId.UniqueThread == p->Threads[i].ClientId.UniqueThread)
                {
                    rows[i].cpuDelta = (p->Threads[i].KernelTime.QuadPart + p->Threads[i].UserTime.QuadPart) -
                                       (prev->Threads[j].KernelTime.QuadPart + prev->Threads[j].UserTime.QuadPart);
                    break;
                }
            }
        }
    }
    if (wantCpu)
        qsort(rows, p->NumberOfThreads, sizeof(TRow), cmp_trows_cpu);

    HANDLE process = detailed ? ntu_open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL) : NULL;

    cJSON *arr = cJSON_CreateArray();
    ULONG emitted = 0;
    for (ULONG i = 0; i < p->NumberOfThreads; i++)
    {
        if (limit && emitted >= limit)
            break;
        cJSON *o = cJSON_CreateObject();
        add_thread_snapshot_fields(o, rows[i].t);
        if (wantCpu)
        {
            double pct = ((double)rows[i].cpuDelta / ((double)sampleMs * 10000.0)) * 100.0;
            cJSON_AddNumberToObject(o, "cpuPercent", (double)((int)(pct * 100 + 0.5)) / 100.0);
        }
        if (detailed)
            add_thread_handle_fields(o, (DWORD)(ULONG_PTR)rows[i].t->ClientId.UniqueThread, process);
        cJSON_AddItemToArray(arr, o);
        emitted++;
    }
    if (process) NtClose(process);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "pid", pid);
    cJSON_AddNumberToObject(result, "threadCount", p->NumberOfThreads);
    cJSON_AddNumberToObject(result, "returned", emitted);
    if (wantCpu) cJSON_AddNumberToObject(result, "cpuSampleMs", (double)sampleMs);
    cJSON_AddItemToObject(result, "threads", arr);

    free(rows);
    snap_free(&s1); if (wantCpu) snap_free(&s2);
    return result;
}

/* ---- thread_details ------------------------------------------------------- */
static cJSON *tool_thread_details(const cJSON *args, int *isError)
{
    DWORD tid; cJSON *err;
    if (!require_tid(args, &tid, &err)) { *isError = 1; return err; }

    NTSTATUS st;
    HANDLE h = ntu_open_thread(tid, THREAD_QUERY_LIMITED_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenThread", st); }
    THREAD_BASIC_INFORMATION tbi;
    st = NtQueryInformationThread(h, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtQueryInformationThread(Basic)", st); }
    DWORD pid = (DWORD)(ULONG_PTR)tbi.ClientId.UniqueProcess;

    ProcSnap s = {0};
    st = snap_take(&s);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("SystemProcessInformation", st); }
    PSYSTEM_PROCESS_INFORMATION p = snap_find(&s, pid);
    cJSON *o = cJSON_CreateObject();
    if (p)
    {
        char name[512];
        proc_name_utf8(p, name, sizeof(name));
        cJSON_AddStringToObject(o, "processName", name);
        for (ULONG i = 0; i < p->NumberOfThreads; i++)
        {
            if ((DWORD)(ULONG_PTR)p->Threads[i].ClientId.UniqueThread == tid)
            {
                add_thread_snapshot_fields(o, &p->Threads[i]);
                break;
            }
        }
    }
    if (!cJSON_GetObjectItemCaseSensitive(o, "tid"))
    {
        cJSON_AddNumberToObject(o, "tid", tid);
        cJSON_AddNumberToObject(o, "pid", pid);
    }
    HANDLE process = ntu_open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL);
    add_thread_handle_fields(o, tid, process);
    if (process) NtClose(process);
    snap_free(&s);
    return o;
}

/* ---- thread actions ------------------------------------------------------- */
static cJSON *thread_suspend_resume(const cJSON *args, int suspend, int *isError)
{
    DWORD tid; cJSON *err;
    if (!require_tid(args, &tid, &err)) { *isError = 1; return err; }
    NTSTATUS st;
    HANDLE h = ntu_open_thread(tid, THREAD_SUSPEND_RESUME, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenThread(THREAD_SUSPEND_RESUME)", st); }
    ULONG prev = 0;
    st = suspend ? NtSuspendThread(h, &prev) : NtResumeThread(h, &prev);
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error(suspend ? "NtSuspendThread" : "NtResumeThread", st); }
    cJSON *o = mcp_ok("%s thread %lu", suspend ? "Suspended" : "Resumed", (unsigned long)tid);
    cJSON_AddNumberToObject(o, "previousSuspendCount", prev);
    return o;
}
static cJSON *tool_suspend_thread(const cJSON *args, int *isError) { return thread_suspend_resume(args, 1, isError); }
static cJSON *tool_resume_thread(const cJSON *args, int *isError) { return thread_suspend_resume(args, 0, isError); }

static cJSON *tool_terminate_thread(const cJSON *args, int *isError)
{
    DWORD tid; cJSON *err;
    if (!require_tid(args, &tid, &err)) { *isError = 1; return err; }
    if (tid == GetCurrentThreadId()) { *isError = 1; return mcp_err("Refusing to terminate the server's own thread"); }
    NTSTATUS st;
    HANDLE h = ntu_open_thread(tid, THREAD_TERMINATE, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenThread(THREAD_TERMINATE)", st); }
    st = NtTerminateThread(h, (NTSTATUS)mcp_arg_i64(args, "exit_code", 0));
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtTerminateThread", st); }
    return mcp_ok("Terminated thread %lu", (unsigned long)tid);
}

static cJSON *tool_set_thread_priority(const cJSON *args, int *isError)
{
    DWORD tid; cJSON *err;
    if (!require_tid(args, &tid, &err)) { *isError = 1; return err; }
    const char *prio = mcp_arg_str(args, "priority", NULL);
    LONG value;
    if (!prio) { *isError = 1; return mcp_err_hint("Valid: idle, lowest, below_normal, normal, above_normal, highest, time_critical.", "Missing 'priority'"); }
    if (_stricmp(prio, "idle") == 0) value = THREAD_PRIORITY_IDLE;
    else if (_stricmp(prio, "lowest") == 0) value = THREAD_PRIORITY_LOWEST;
    else if (_stricmp(prio, "below_normal") == 0) value = THREAD_PRIORITY_BELOW_NORMAL;
    else if (_stricmp(prio, "normal") == 0) value = THREAD_PRIORITY_NORMAL;
    else if (_stricmp(prio, "above_normal") == 0) value = THREAD_PRIORITY_ABOVE_NORMAL;
    else if (_stricmp(prio, "highest") == 0) value = THREAD_PRIORITY_HIGHEST;
    else if (_stricmp(prio, "time_critical") == 0) value = THREAD_PRIORITY_TIME_CRITICAL;
    else { *isError = 1; return mcp_err_hint("Valid: idle, lowest, below_normal, normal, above_normal, highest, time_critical.", "Invalid 'priority' %s", prio); }

    HANDLE h = OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
    if (!h) { *isError = 1; return ntu_win_error("OpenThread", GetLastError()); }
    BOOL ok = SetThreadPriority(h, value);
    DWORD e = GetLastError();
    CloseHandle(h);
    if (!ok) { *isError = 1; return ntu_win_error("SetThreadPriority", e); }
    return mcp_ok("Set thread %lu priority to %s", (unsigned long)tid, prio);
}

static cJSON *tool_set_thread_affinity(const cJSON *args, int *isError)
{
    DWORD tid; cJSON *err;
    if (!require_tid(args, &tid, &err)) { *isError = 1; return err; }
    int found = 0;
    unsigned long long mask = mcp_arg_u64(args, "affinity_mask", 0, &found);
    if (!found || !mask) { *isError = 1; return mcp_err_hint("Bitmask of allowed CPUs, e.g. 0x1 for CPU 0.", "Missing or zero 'affinity_mask'"); }
    HANDLE h = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) { *isError = 1; return ntu_win_error("OpenThread", GetLastError()); }
    DWORD_PTR prev = SetThreadAffinityMask(h, (DWORD_PTR)mask);
    DWORD e = GetLastError();
    CloseHandle(h);
    if (!prev) { *isError = 1; return ntu_win_error("SetThreadAffinityMask", e); }
    cJSON *o = mcp_ok("Set thread %lu affinity to 0x%llX", (unsigned long)tid, mask);
    char pb[32];
    _snprintf_s(pb, sizeof(pb), _TRUNCATE, "0x%llX", (unsigned long long)prev);
    cJSON_AddStringToObject(o, "previousAffinityMask", pb);
    return o;
}

/* ---- registration --------------------------------------------------------- */
#define TID_PROP "\"tid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Thread id (number or decimal/hex string). Find it with process_threads.\"}"
#define CONFIRM_PROP "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true. This tool changes the system; the call is refused without explicit confirmation.\"}"

static const Tool g_thread_tools[] = {
    { "process_threads", "List threads of a process",
      "The System Informer 'Threads' page for one process: every thread with tid, state (Running/Waiting/...), "
      "wait reason, priorities, context switches, CPU times, creation time, start address (raw and resolved "
      "to module+offset), suspend count, I/O pending, thread name, and a measured CPU %. Sorted by CPU by "
      "default so hot threads come first. Use to find which thread is burning CPU or is stuck.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Owning process id.\"},"
      "\"sort_by\":{\"type\":\"string\",\"enum\":[\"cpu\",\"tid\"],\"default\":\"cpu\",\"description\":\"'cpu' samples over sample_ms and sorts hottest first.\"},"
      "\"detailed\":{\"type\":\"boolean\",\"default\":true,\"description\":\"Open each thread for start address/name/suspend count. Set false for a fast summary.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":0,\"description\":\"Max threads to return (0 = all).\"},"
      "\"sample_ms\":{\"type\":\"integer\",\"default\":300,\"description\":\"CPU sampling window in ms.\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_process_threads },

    { "thread_details", "Thread details",
      "Full detail for one thread by tid (owning process name/pid, state, wait reason, priorities, times, "
      "start address raw+symbolic, TEB address, suspend count, thread name, affinity).",
      "{\"type\":\"object\",\"properties\":{" TID_PROP "},\"required\":[\"tid\"],\"additionalProperties\":false}", 0, tool_thread_details },

    { "suspend_thread", "Suspend thread",
      "GUARDED (confirm=true required). Suspend a single thread (System Informer thread context menu > Suspend). "
      "Returns the previous suspend count.",
      "{\"type\":\"object\",\"properties\":{" TID_PROP "," CONFIRM_PROP "},\"required\":[\"tid\",\"confirm\"],\"additionalProperties\":false}", 1, tool_suspend_thread },

    { "resume_thread", "Resume thread",
      "GUARDED (confirm=true required). Decrement a thread's suspend count; it runs again when the count "
      "reaches zero.",
      "{\"type\":\"object\",\"properties\":{" TID_PROP "," CONFIRM_PROP "},\"required\":[\"tid\",\"confirm\"],\"additionalProperties\":false}", 1, tool_resume_thread },

    { "terminate_thread", "Terminate thread",
      "GUARDED (confirm=true required). Kill one thread. Dangerous: the owning process may deadlock or "
      "crash because locks held by that thread are never released. Prefer terminate_process for whole "
      "processes.",
      "{\"type\":\"object\",\"properties\":{" TID_PROP ","
      "\"exit_code\":{\"type\":\"integer\",\"default\":0}," CONFIRM_PROP
      "},\"required\":[\"tid\",\"confirm\"],\"additionalProperties\":false}", 1, tool_terminate_thread },

    { "set_thread_priority", "Set thread priority",
      "GUARDED (confirm=true required). Change one thread's relative priority (System Informer thread "
      "'Priority' menu).",
      "{\"type\":\"object\",\"properties\":{" TID_PROP ","
      "\"priority\":{\"type\":\"string\",\"enum\":[\"idle\",\"lowest\",\"below_normal\",\"normal\",\"above_normal\",\"highest\",\"time_critical\"]},"
      CONFIRM_PROP "},\"required\":[\"tid\",\"priority\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_thread_priority },

    { "set_thread_affinity", "Set thread affinity",
      "GUARDED (confirm=true required). Restrict which CPUs a thread may run on (bitmask, bit N = CPU N). "
      "Must be a subset of the process affinity.",
      "{\"type\":\"object\",\"properties\":{" TID_PROP ","
      "\"affinity_mask\":{\"type\":[\"integer\",\"string\"],\"description\":\"CPU bitmask, e.g. \\\"0x1\\\".\"},"
      CONFIRM_PROP "},\"required\":[\"tid\",\"affinity_mask\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_thread_affinity },
};

void register_thread_tools(void)
{
    for (size_t i = 0; i < sizeof(g_thread_tools) / sizeof(g_thread_tools[0]); i++)
        mcp_register_tool(&g_thread_tools[i]);
}
