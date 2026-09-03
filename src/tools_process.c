#include "procsnap.h"
#include "mcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <shellapi.h>
#include <dbghelp.h>

/* ===========================================================================
 * Shared helpers
 * ========================================================================= */

/* Fills the common per-process fields shared by list_processes and process_details. */
static void add_snapshot_fields(cJSON *o, PSYSTEM_PROCESS_INFORMATION p)
{
    DWORD pid = (DWORD)(ULONG_PTR)p->UniqueProcessId;
    char name[512];
    proc_name_utf8(p, name, sizeof(name));
    cJSON_AddNumberToObject(o, "pid", pid);
    cJSON_AddStringToObject(o, "name", name);
    cJSON_AddNumberToObject(o, "parentPid", (double)(ULONG_PTR)p->InheritedFromUniqueProcessId);
    cJSON_AddNumberToObject(o, "sessionId", p->SessionId);
    cJSON_AddNumberToObject(o, "threads", p->NumberOfThreads);
    cJSON_AddNumberToObject(o, "handles", p->HandleCount);
    cJSON_AddNumberToObject(o, "basePriority", p->BasePriority);
    ntu_add_bytes(o, "workingSet", p->WorkingSetSize);
    ntu_add_bytes(o, "privateBytes", p->PagefileUsage);
    ntu_add_bytes(o, "virtualSize", p->VirtualSize);
    char t[32];
    ntu_time_to_iso(p->CreateTime.QuadPart, t, sizeof(t));
    cJSON_AddStringToObject(o, "createTime", t);
    cJSON_AddNumberToObject(o, "userTimeMs", (double)(p->UserTime.QuadPart / 10000));
    cJSON_AddNumberToObject(o, "kernelTimeMs", (double)(p->KernelTime.QuadPart / 10000));
}

/* Adds fields that require opening the process. Fails silently per field. */
static void add_handle_fields(cJSON *o, DWORD pid, int wantCmdLine)
{
    if (pid == 0 || pid == 4)
        return;
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, &st);
    if (!h)
    {
        char code[16];
        _snprintf_s(code, sizeof(code), _TRUNCATE, "0x%08lX", (unsigned long)st);
        cJSON_AddStringToObject(o, "openError", code);
        return;
    }
    char *path = ntu_process_image_path(h);
    if (path) { cJSON_AddStringToObject(o, "imagePath", path); free(path); }
    if (wantCmdLine)
    {
        char *cmd = ntu_process_command_line(h);
        if (cmd) { cJSON_AddStringToObject(o, "commandLine", cmd); free(cmd); }
    }

    ULONG_PTR wow = 0;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessWow64Information, &wow, sizeof(wow), NULL)))
        cJSON_AddBoolToObject(o, "is32Bit", wow ? 1 : 0);

    PROCESS_PRIORITY_CLASS ppc;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessPriorityClass, &ppc, sizeof(ppc), NULL)))
        cJSON_AddStringToObject(o, "priorityClass", priority_class_name(ppc.PriorityClass));

    PS_PROTECTION prot;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessProtectionInformation, &prot, sizeof(prot), NULL)))
    {
        const char *type = prot.Type == PsProtectedTypeNone ? "none" :
                           prot.Type == PsProtectedTypeProtectedLight ? "PPL" :
                           prot.Type == PsProtectedTypeProtected ? "Protected" : "unknown";
        cJSON_AddStringToObject(o, "protection", type);
    }

    ULONG breakOnTerm = 0;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessBreakOnTermination, &breakOnTerm, sizeof(breakOnTerm), NULL)))
        cJSON_AddBoolToObject(o, "critical", breakOnTerm ? 1 : 0);

    PROCESS_BASIC_INFORMATION pbi;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
    {
        cJSON_AddBoolToObject(o, "running", pbi.ExitStatus == STATUS_PENDING ? 1 : 0);
        char peb[32];
        _snprintf_s(peb, sizeof(peb), _TRUNCATE, "0x%p", (void *)pbi.PebBaseAddress);
        cJSON_AddStringToObject(o, "pebAddress", peb);
    }

    /* affinity */
    KAFFINITY affinity = 0;
    if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessAffinityMask, &affinity, sizeof(affinity), NULL)))
    {
        char mask[32];
        _snprintf_s(mask, sizeof(mask), _TRUNCATE, "0x%llX", (unsigned long long)affinity);
        cJSON_AddStringToObject(o, "affinityMask", mask);
    }

    /* current directory / DEP / etc are too deep for the summary */
    add_token_summary(o, h);
    NtClose(h);
}

static int name_matches(PSYSTEM_PROCESS_INFORMATION p, const char *filter)
{
    if (!filter || !filter[0])
        return 1;
    char name[512];
    proc_name_utf8(p, name, sizeof(name));
    size_t fl = strlen(filter), nl = strlen(name);
    if (fl > nl)
        return 0;
    for (size_t i = 0; i + fl <= nl; i++)
        if (_strnicmp(name + i, filter, fl) == 0)
            return 1;
    return 0;
}

/* Every process tool that takes a pid uses this. */
static int require_pid(const cJSON *args, DWORD *pid, cJSON **err)
{
    int found = 0;
    unsigned long long v = mcp_arg_u64(args, "pid", 0, &found);
    if (!found)
    {
        *err = mcp_err_hint("Pass the process id as \"pid\" (number or string). Use list_processes to find it.", "Missing required argument: pid");
        return 0;
    }
    *pid = (DWORD)v;
    return 1;
}

/* ===========================================================================
 * list_processes
 * ========================================================================= */
typedef struct Row { PSYSTEM_PROCESS_INFORMATION p; double cpu; } Row;

static const char *g_sort_key;
static int cmp_rows(const void *a, const void *b)
{
    const Row *ra = (const Row *)a, *rb = (const Row *)b;
    if (strcmp(g_sort_key, "cpu") == 0)
        return (ra->cpu < rb->cpu) - (ra->cpu > rb->cpu);
    if (strcmp(g_sort_key, "memory") == 0)
        return (ra->p->WorkingSetSize < rb->p->WorkingSetSize) - (ra->p->WorkingSetSize > rb->p->WorkingSetSize);
    if (strcmp(g_sort_key, "private") == 0)
        return (ra->p->PagefileUsage < rb->p->PagefileUsage) - (ra->p->PagefileUsage > rb->p->PagefileUsage);
    if (strcmp(g_sort_key, "threads") == 0)
        return (int)rb->p->NumberOfThreads - (int)ra->p->NumberOfThreads;
    if (strcmp(g_sort_key, "handles") == 0)
        return (int)rb->p->HandleCount - (int)ra->p->HandleCount;
    if (strcmp(g_sort_key, "name") == 0)
    {
        char na[512], nb[512];
        proc_name_utf8(ra->p, na, sizeof(na));
        proc_name_utf8(rb->p, nb, sizeof(nb));
        return _stricmp(na, nb);
    }
    if (strcmp(g_sort_key, "start_time") == 0)
        return (ra->p->CreateTime.QuadPart < rb->p->CreateTime.QuadPart) - (ra->p->CreateTime.QuadPart > rb->p->CreateTime.QuadPart);
    return (int)((LONG_PTR)ra->p->UniqueProcessId - (LONG_PTR)rb->p->UniqueProcessId);
}

static cJSON *tool_list_processes(const cJSON *args, int *isError)
{
    const char *sortBy = mcp_arg_str(args, "sort_by", "pid");
    const char *filter = mcp_arg_str(args, "name_filter", NULL);
    unsigned long long limit = mcp_arg_u64(args, "limit", 0, NULL);
    int includePaths = mcp_arg_bool(args, "include_paths", 0);
    int wantCpu = strcmp(sortBy, "cpu") == 0 || mcp_arg_bool(args, "include_cpu", 0);
    unsigned long long sampleMs = mcp_arg_u64(args, "sample_ms", 500, NULL);
    if (sampleMs < 100) sampleMs = 100;
    if (sampleMs > 5000) sampleMs = 5000;

    ProcSnap s1 = {0}, s2 = {0};
    NTSTATUS st = snap_take(&s1);
    if (!NT_SUCCESS(st))
    {
        *isError = 1;
        return ntu_status_error("SystemProcessInformation", st);
    }
    if (wantCpu)
    {
        Sleep((DWORD)sampleMs);
        st = snap_take(&s2);
        if (!NT_SUCCESS(st))
        {
            snap_free(&s1);
            *isError = 1;
            return ntu_status_error("SystemProcessInformation (2nd sample)", st);
        }
    }
    ProcSnap *cur = wantCpu ? &s2 : &s1;

    SYSTEM_BASIC_INFORMATION basic;
    ULONG cpus = 1;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL)))
        cpus = basic.NumberOfProcessors ? basic.NumberOfProcessors : 1;

    size_t count = 0;
    SNAP_FOREACH(cur, p) count++;
    Row *rows = (Row *)calloc(count ? count : 1, sizeof(Row));
    size_t n = 0;
    SNAP_FOREACH(cur, p)
    {
        if (!name_matches(p, filter))
            continue;
        rows[n].p = p;
        rows[n].cpu = 0.0;
        if (wantCpu)
        {
            PSYSTEM_PROCESS_INFORMATION prev = snap_find(&s1, (DWORD)(ULONG_PTR)p->UniqueProcessId);
            if (prev && prev->CreateTime.QuadPart == p->CreateTime.QuadPart)
            {
                LONG64 d = (p->KernelTime.QuadPart + p->UserTime.QuadPart) -
                           (prev->KernelTime.QuadPart + prev->UserTime.QuadPart);
                double wall = (double)sampleMs * 10000.0 * (double)cpus;
                if (wall > 0 && d > 0)
                    rows[n].cpu = ((double)d / wall) * 100.0;
            }
        }
        n++;
    }

    g_sort_key = sortBy;
    qsort(rows, n, sizeof(Row), cmp_rows);

    cJSON *arr = cJSON_CreateArray();
    size_t emitted = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (limit && emitted >= limit)
            break;
        /* skip the idle process for cpu sort (it dominates otherwise) */
        DWORD pid = (DWORD)(ULONG_PTR)rows[i].p->UniqueProcessId;
        if (wantCpu && pid == 0)
            continue;
        cJSON *o = cJSON_CreateObject();
        add_snapshot_fields(o, rows[i].p);
        if (wantCpu)
            cJSON_AddNumberToObject(o, "cpuPercent", (double)((int)(rows[i].cpu * 100 + 0.5)) / 100.0);
        if (includePaths)
            add_handle_fields(o, pid, 0);
        cJSON_AddItemToArray(arr, o);
        emitted++;
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "total", (double)n);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    cJSON_AddStringToObject(result, "sortedBy", sortBy);
    if (wantCpu)
        cJSON_AddNumberToObject(result, "cpuSampleMs", (double)sampleMs);
    cJSON_AddItemToObject(result, "processes", arr);

    free(rows);
    snap_free(&s1);
    if (wantCpu) snap_free(&s2);
    return result;
}

/* ===========================================================================
 * process_tree
 * ========================================================================= */
static cJSON *build_tree_node(const ProcSnap *s, PSYSTEM_PROCESS_INFORMATION p, int depth)
{
    cJSON *o = cJSON_CreateObject();
    char name[512];
    proc_name_utf8(p, name, sizeof(name));
    DWORD pid = (DWORD)(ULONG_PTR)p->UniqueProcessId;
    cJSON_AddNumberToObject(o, "pid", pid);
    cJSON_AddStringToObject(o, "name", name);
    ntu_add_bytes(o, "workingSet", p->WorkingSetSize);
    cJSON *children = cJSON_CreateArray();
    if (depth < 64)
    {
        SNAP_FOREACH(s, c)
        {
            if (c == p)
                continue;
            if ((DWORD)(ULONG_PTR)c->InheritedFromUniqueProcessId != pid)
                continue;
            /* PID reuse guard: a real child must have been created after the parent */
            if (c->CreateTime.QuadPart < p->CreateTime.QuadPart)
                continue;
            cJSON_AddItemToArray(children, build_tree_node(s, c, depth + 1));
        }
    }
    cJSON_AddItemToObject(o, "children", children);
    return o;
}

static cJSON *tool_process_tree(const cJSON *args, int *isError)
{
    int rootFound = 0;
    unsigned long long rootPid = mcp_arg_u64(args, "root_pid", 0, &rootFound);

    ProcSnap s = {0};
    NTSTATUS st = snap_take(&s);
    if (!NT_SUCCESS(st))
    {
        *isError = 1;
        return ntu_status_error("SystemProcessInformation", st);
    }

    cJSON *roots = cJSON_CreateArray();
    if (rootFound)
    {
        PSYSTEM_PROCESS_INFORMATION p = snap_find(&s, (DWORD)rootPid);
        if (!p)
        {
            snap_free(&s);
            *isError = 1;
            return mcp_err("No process with pid %llu", rootPid);
        }
        cJSON_AddItemToArray(roots, build_tree_node(&s, p, 0));
    }
    else
    {
        SNAP_FOREACH(&s, p)
        {
            DWORD ppid = (DWORD)(ULONG_PTR)p->InheritedFromUniqueProcessId;
            PSYSTEM_PROCESS_INFORMATION parent = ppid ? snap_find(&s, ppid) : NULL;
            /* root if no parent, parent is itself, or parent is younger (pid reuse) */
            int isRoot = !parent || parent == p || parent->CreateTime.QuadPart > p->CreateTime.QuadPart;
            if (isRoot)
                cJSON_AddItemToArray(roots, build_tree_node(&s, p, 0));
        }
    }
    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "roots", roots);
    snap_free(&s);
    return result;
}

/* ===========================================================================
 * process_details
 * ========================================================================= */
static cJSON *tool_process_details(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }

    ProcSnap s = {0};
    NTSTATUS st = snap_take(&s);
    if (!NT_SUCCESS(st))
    {
        *isError = 1;
        return ntu_status_error("SystemProcessInformation", st);
    }
    PSYSTEM_PROCESS_INFORMATION p = snap_find(&s, pid);
    if (!p)
    {
        snap_free(&s);
        *isError = 1;
        return mcp_err_hint("The process may have exited. Use list_processes to get current pids.", "No process with pid %lu", (unsigned long)pid);
    }

    cJSON *o = cJSON_CreateObject();
    add_snapshot_fields(o, p);

    /* parent name */
    DWORD ppid = (DWORD)(ULONG_PTR)p->InheritedFromUniqueProcessId;
    PSYSTEM_PROCESS_INFORMATION parent = snap_find(&s, ppid);
    if (parent && parent->CreateTime.QuadPart <= p->CreateTime.QuadPart)
    {
        char pn[512];
        proc_name_utf8(parent, pn, sizeof(pn));
        cJSON_AddStringToObject(o, "parentName", pn);
    }
    else if (ppid)
    {
        cJSON_AddStringToObject(o, "parentName", "(exited or pid reused)");
    }

    /* IO counters & extra memory */
    ntu_add_bytes(o, "peakWorkingSet", p->PeakWorkingSetSize);
    ntu_add_bytes(o, "peakPrivateBytes", p->PeakPagefileUsage);
    ntu_add_bytes(o, "workingSetPrivate", p->WorkingSetPrivateSize);
    ntu_add_bytes(o, "pagedPool", p->QuotaPagedPoolUsage);
    ntu_add_bytes(o, "nonPagedPool", p->QuotaNonPagedPoolUsage);
    cJSON_AddNumberToObject(o, "pageFaults", p->PageFaultCount);
    cJSON_AddNumberToObject(o, "hardFaults", p->HardFaultCount);
    cJSON *io = cJSON_CreateObject();
    cJSON_AddNumberToObject(io, "reads", (double)p->ReadOperationCount.QuadPart);
    cJSON_AddNumberToObject(io, "writes", (double)p->WriteOperationCount.QuadPart);
    cJSON_AddNumberToObject(io, "other", (double)p->OtherOperationCount.QuadPart);
    ntu_add_bytes(io, "readBytes", (unsigned long long)p->ReadTransferCount.QuadPart);
    ntu_add_bytes(io, "writeBytes", (unsigned long long)p->WriteTransferCount.QuadPart);
    ntu_add_bytes(io, "otherBytes", (unsigned long long)p->OtherTransferCount.QuadPart);
    cJSON_AddItemToObject(o, "io", io);
    cJSON_AddNumberToObject(o, "cycleTime", (double)p->CycleTime);

    add_handle_fields(o, pid, 1);

    /* things that need PROCESS_VM_READ / more access */
    if (pid != 0 && pid != 4)
    {
        HANDLE h = ntu_open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL);
        if (h)
        {
            /* current directory + environment size via PEB user process parameters */
            PROCESS_BASIC_INFORMATION pbi;
            if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)) && pbi.PebBaseAddress)
            {
                PEB peb;
                SIZE_T rd = 0;
                if (NT_SUCCESS(NtReadVirtualMemory(h, pbi.PebBaseAddress, &peb, sizeof(peb), &rd)) && peb.ProcessParameters)
                {
                    RTL_USER_PROCESS_PARAMETERS upp;
                    if (NT_SUCCESS(NtReadVirtualMemory(h, peb.ProcessParameters, &upp, sizeof(upp), &rd)))
                    {
                        if (upp.CurrentDirectory.DosPath.Buffer && upp.CurrentDirectory.DosPath.Length && upp.CurrentDirectory.DosPath.Length < 0x8000)
                        {
                            PWSTR wbuf = (PWSTR)malloc(upp.CurrentDirectory.DosPath.Length + sizeof(WCHAR));
                            if (wbuf && NT_SUCCESS(NtReadVirtualMemory(h, upp.CurrentDirectory.DosPath.Buffer, wbuf, upp.CurrentDirectory.DosPath.Length, &rd)))
                                ntu_add_wn(o, "currentDirectory", wbuf, (int)(upp.CurrentDirectory.DosPath.Length / sizeof(WCHAR)));
                            free(wbuf);
                        }
                        cJSON_AddBoolToObject(o, "beingDebugged", peb.BeingDebugged ? 1 : 0);
                    }
                }
            }
            /* DEP / mitigation summary */
            ULONG dep = 0;
            if (NT_SUCCESS(NtQueryInformationProcess(h, ProcessExecuteFlags, &dep, sizeof(dep), NULL)))
                cJSON_AddBoolToObject(o, "depEnabled", (dep & MEM_EXECUTE_OPTION_DISABLE) ? 1 : 0);
            /* job */
            BOOL inJob = FALSE;
            if (IsProcessInJob(h, NULL, &inJob))
                cJSON_AddBoolToObject(o, "inJob", inJob ? 1 : 0);
            /* GDI/USER handles */
            cJSON_AddNumberToObject(o, "gdiHandles", GetGuiResources(h, GR_GDIOBJECTS));
            cJSON_AddNumberToObject(o, "userHandles", GetGuiResources(h, GR_USEROBJECTS));
            NtClose(h);
        }
    }

    snap_free(&s);
    return o;
}

/* ===========================================================================
 * process_token
 * ========================================================================= */
static const char *sid_attr_flags(DWORD attr, char *buf, size_t cap)
{
    buf[0] = 0;
    if (attr & SE_GROUP_ENABLED) strcat_s(buf, cap, "enabled,");
    if (attr & SE_GROUP_ENABLED_BY_DEFAULT) strcat_s(buf, cap, "default,");
    if (attr & SE_GROUP_MANDATORY) strcat_s(buf, cap, "mandatory,");
    if (attr & SE_GROUP_OWNER) strcat_s(buf, cap, "owner,");
    if (attr & SE_GROUP_USE_FOR_DENY_ONLY) strcat_s(buf, cap, "deny_only,");
    if (attr & SE_GROUP_INTEGRITY) strcat_s(buf, cap, "integrity,");
    if (attr & SE_GROUP_LOGON_ID) strcat_s(buf, cap, "logon_id,");
    size_t l = strlen(buf);
    if (l) buf[l - 1] = 0;
    return buf;
}

static cJSON *tool_process_token(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }

    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess", st); }
    HANDLE token;
    st = NtOpenProcessToken(h, TOKEN_QUERY, &token);
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtOpenProcessToken", st); }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "pid", pid);

    ULONG len = 0;
    /* user, integrity, elevation */
    {
        HANDLE dummy = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (dummy) { add_token_summary(o, dummy); CloseHandle(dummy); }
    }

    /* token type / impersonation */
    TOKEN_TYPE tt;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenType, &tt, sizeof(tt), &len)))
        cJSON_AddStringToObject(o, "tokenType", tt == TokenPrimary ? "primary" : "impersonation");

    /* session, virtualization, UIAccess, app container */
    ULONG v = 0;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenSessionId, &v, sizeof(v), &len)))
        cJSON_AddNumberToObject(o, "sessionId", v);
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenVirtualizationEnabled, &v, sizeof(v), &len)))
        cJSON_AddBoolToObject(o, "virtualizationEnabled", v ? 1 : 0);
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenUIAccess, &v, sizeof(v), &len)))
        cJSON_AddBoolToObject(o, "uiAccess", v ? 1 : 0);
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenIsAppContainer, &v, sizeof(v), &len)))
        cJSON_AddBoolToObject(o, "appContainer", v ? 1 : 0);

    /* owner / primary group */
    UCHAR ownerBuf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_OWNER)];
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenOwner, ownerBuf, sizeof(ownerBuf), &len)))
    {
        char *acct = ntu_sid_account(((PTOKEN_OWNER)ownerBuf)->Owner);
        if (acct) { cJSON_AddStringToObject(o, "owner", acct); free(acct); }
    }

    /* logon session / auth id */
    TOKEN_STATISTICS stats;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &len)))
    {
        char luid[32];
        _snprintf_s(luid, sizeof(luid), _TRUNCATE, "0x%08lX:0x%08lX", stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart);
        cJSON_AddStringToObject(o, "authenticationId", luid);
        cJSON_AddStringToObject(o, "impersonationLevel",
            stats.TokenType == TokenPrimary ? "n/a" :
            stats.ImpersonationLevel == SecurityAnonymous ? "anonymous" :
            stats.ImpersonationLevel == SecurityIdentification ? "identification" :
            stats.ImpersonationLevel == SecurityImpersonation ? "impersonation" : "delegation");
        cJSON_AddNumberToObject(o, "groupCount", stats.GroupCount);
        cJSON_AddNumberToObject(o, "privilegeCount", stats.PrivilegeCount);
    }

    /* groups */
    NtQueryInformationToken(token, TokenGroups, NULL, 0, &len);
    if (len)
    {
        PTOKEN_GROUPS tg = (PTOKEN_GROUPS)malloc(len);
        if (tg && NT_SUCCESS(NtQueryInformationToken(token, TokenGroups, tg, len, &len)))
        {
            cJSON *groups = cJSON_CreateArray();
            for (ULONG i = 0; i < tg->GroupCount; i++)
            {
                cJSON *g = cJSON_CreateObject();
                char *acct = ntu_sid_account(tg->Groups[i].Sid);
                char *sid = ntu_sid_to_string(tg->Groups[i].Sid);
                cJSON_AddStringToObject(g, "name", acct ? acct : (sid ? sid : "?"));
                if (sid) cJSON_AddStringToObject(g, "sid", sid);
                char flags[128];
                cJSON_AddStringToObject(g, "attributes", sid_attr_flags(tg->Groups[i].Attributes, flags, sizeof(flags)));
                cJSON_AddItemToArray(groups, g);
                free(acct); free(sid);
            }
            cJSON_AddItemToObject(o, "groups", groups);
        }
        free(tg);
    }

    /* privileges */
    len = 0;
    NtQueryInformationToken(token, TokenPrivileges, NULL, 0, &len);
    if (len)
    {
        PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(len);
        if (tp && NT_SUCCESS(NtQueryInformationToken(token, TokenPrivileges, tp, len, &len)))
        {
            cJSON *privs = cJSON_CreateArray();
            for (ULONG i = 0; i < tp->PrivilegeCount; i++)
            {
                cJSON *pv = cJSON_CreateObject();
                WCHAR name[128];
                DWORD nlen = 128;
                if (LookupPrivilegeNameW(NULL, &tp->Privileges[i].Luid, name, &nlen))
                    ntu_add_w(pv, "name", name);
                else
                    cJSON_AddStringToObject(pv, "name", "?");
                DWORD a = tp->Privileges[i].Attributes;
                cJSON_AddStringToObject(pv, "state",
                    (a & SE_PRIVILEGE_ENABLED) ? ((a & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? "enabled (default)" : "enabled") :
                    (a & SE_PRIVILEGE_REMOVED) ? "removed" : "disabled");
                cJSON_AddItemToArray(privs, pv);
            }
            cJSON_AddItemToObject(o, "privileges", privs);
        }
        free(tp);
    }

    NtClose(token);
    return o;
}

/* ===========================================================================
 * launch_process / launch_process_elevated
 * ========================================================================= */
static cJSON *do_launch(const cJSON *args, int elevated, int *isError)
{
    const char *cmd = mcp_arg_str(args, "command_line", NULL);
    const char *cwd = mcp_arg_str(args, "working_directory", NULL);
    const char *show = mcp_arg_str(args, "window", "normal");
    if (!cmd || !cmd[0])
    {
        *isError = 1;
        return mcp_err_hint("Provide the program (and arguments) to run, e.g. \"notepad.exe C:\\\\file.txt\".", "Missing required argument: command_line");
    }

    int showCmd = SW_SHOWNORMAL;
    if (_stricmp(show, "hidden") == 0) showCmd = SW_HIDE;
    else if (_stricmp(show, "minimized") == 0) showCmd = SW_SHOWMINIMIZED;
    else if (_stricmp(show, "maximized") == 0) showCmd = SW_SHOWMAXIMIZED;

    PWSTR wcmd = ntu_u2w(cmd);
    PWSTR wcwd = cwd ? ntu_u2w(cwd) : NULL;

    cJSON *o = cJSON_CreateObject();
    if (elevated)
    {
        /* ShellExecuteEx with runas -> UAC prompt. Split file/args. */
        int argc = 0;
        LPWSTR *argv = CommandLineToArgvW(wcmd, &argc);
        if (!argv || argc == 0)
        {
            free(wcmd); free(wcwd);
            *isError = 1;
            cJSON_Delete(o);
            return mcp_err("Could not parse command_line");
        }
        /* args = everything after the first token in the original string */
        PWSTR params = NULL;
        {
            PWSTR p = wcmd;
            if (*p == L'"') { p++; while (*p && *p != L'"') p++; if (*p) p++; }
            else { while (*p && *p != L' ') p++; }
            while (*p == L' ') p++;
            params = *p ? p : NULL;
        }
        SHELLEXECUTEINFOW sei;
        memset(&sei, 0, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = L"runas";
        sei.lpFile = argv[0];
        sei.lpParameters = params;
        sei.lpDirectory = wcwd;
        sei.nShow = showCmd;
        if (!ShellExecuteExW(&sei))
        {
            DWORD e = GetLastError();
            LocalFree(argv); free(wcmd); free(wcwd);
            cJSON_Delete(o);
            *isError = 1;
            if (e == ERROR_CANCELLED)
                return mcp_err_hint("The user declined the UAC consent prompt.", "Elevated launch was cancelled");
            return ntu_win_error("ShellExecuteEx(runas)", e);
        }
        DWORD pid = sei.hProcess ? GetProcessId(sei.hProcess) : 0;
        cJSON_AddStringToObject(o, "status", "ok");
        cJSON_AddNumberToObject(o, "pid", pid);
        cJSON_AddBoolToObject(o, "elevated", 1);
        if (sei.hProcess) CloseHandle(sei.hProcess);
        LocalFree(argv);
    }
    else
    {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = (WORD)showCmd;
        /* CreateProcess may modify the command line buffer */
        if (!CreateProcessW(NULL, wcmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, wcwd, &si, &pi))
        {
            DWORD e = GetLastError();
            free(wcmd); free(wcwd);
            cJSON_Delete(o);
            *isError = 1;
            return ntu_win_error("CreateProcess", e);
        }
        cJSON_AddStringToObject(o, "status", "ok");
        cJSON_AddNumberToObject(o, "pid", pi.dwProcessId);
        cJSON_AddNumberToObject(o, "mainThreadId", pi.dwThreadId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    cJSON_AddStringToObject(o, "commandLine", cmd);
    free(wcmd); free(wcwd);
    return o;
}

static cJSON *tool_launch_process(const cJSON *args, int *isError) { return do_launch(args, 0, isError); }
static cJSON *tool_launch_process_elevated(const cJSON *args, int *isError) { return do_launch(args, 1, isError); }

/* ===========================================================================
 * Control actions
 * ========================================================================= */
static cJSON *tool_terminate_process(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
    {
        *isError = 1;
        return mcp_err("Refusing to terminate pid %lu (system or this server)", (unsigned long)pid);
    }
    long long exitCode = mcp_arg_i64(args, "exit_code", 1);
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_TERMINATE)", st); }

    /* warn about critical processes */
    ULONG crit = 0;
    NtQueryInformationProcess(h, ProcessBreakOnTermination, &crit, sizeof(crit), NULL);
    if (crit && !mcp_arg_bool(args, "allow_critical", 0))
    {
        NtClose(h);
        *isError = 1;
        return mcp_err_hint("Terminating a critical process bugchecks (crashes) Windows. If you really intend this, pass allow_critical=true.",
            "pid %lu is marked critical; refusing", (unsigned long)pid);
    }
    char *path = ntu_process_image_path(h);
    st = NtTerminateProcess(h, (NTSTATUS)exitCode);
    NtClose(h);
    if (!NT_SUCCESS(st)) { free(path); *isError = 1; return ntu_status_error("NtTerminateProcess", st); }
    cJSON *o = mcp_ok("Terminated pid %lu", (unsigned long)pid);
    if (path) { cJSON_AddStringToObject(o, "imagePath", path); free(path); }
    return o;
}

static void collect_descendants(const ProcSnap *s, DWORD pid, LONG64 parentCreate, cJSON *arr)
{
    SNAP_FOREACH(s, c)
    {
        if ((DWORD)(ULONG_PTR)c->InheritedFromUniqueProcessId != pid)
            continue;
        if (c->CreateTime.QuadPart < parentCreate)
            continue;
        DWORD cpid = (DWORD)(ULONG_PTR)c->UniqueProcessId;
        if (cpid == pid)
            continue;
        collect_descendants(s, cpid, c->CreateTime.QuadPart, arr);
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(cpid));
    }
}

static cJSON *tool_terminate_process_tree(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
    {
        *isError = 1;
        return mcp_err("Refusing to terminate pid %lu (system or this server)", (unsigned long)pid);
    }
    ProcSnap s = {0};
    NTSTATUS st = snap_take(&s);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("SystemProcessInformation", st); }
    PSYSTEM_PROCESS_INFORMATION root = snap_find(&s, pid);
    if (!root) { snap_free(&s); *isError = 1; return mcp_err("No process with pid %lu", (unsigned long)pid); }

    cJSON *targets = cJSON_CreateArray();   /* children first (post-order), then root */
    collect_descendants(&s, pid, root->CreateTime.QuadPart, targets);
    cJSON_AddItemToArray(targets, cJSON_CreateNumber(pid));
    snap_free(&s);

    cJSON *killed = cJSON_CreateArray();
    cJSON *failed = cJSON_CreateArray();
    cJSON *it;
    cJSON_ArrayForEach(it, targets)
    {
        DWORD t = (DWORD)it->valuedouble;
        HANDLE h = ntu_open_process(t, PROCESS_TERMINATE, &st);
        if (h && NT_SUCCESS(st = NtTerminateProcess(h, 1)))
            cJSON_AddItemToArray(killed, cJSON_CreateNumber(t));
        else
        {
            cJSON *f = cJSON_CreateObject();
            cJSON_AddNumberToObject(f, "pid", t);
            char code[16];
            _snprintf_s(code, sizeof(code), _TRUNCATE, "0x%08lX", (unsigned long)st);
            cJSON_AddStringToObject(f, "ntstatus", code);
            cJSON_AddItemToArray(failed, f);
        }
        if (h) NtClose(h);
    }
    cJSON_Delete(targets);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", cJSON_GetArraySize(failed) ? "partial" : "ok");
    cJSON_AddItemToObject(o, "terminated", killed);
    cJSON_AddItemToObject(o, "failed", failed);
    return o;
}

static cJSON *suspend_resume(const cJSON *args, int suspend, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
    {
        *isError = 1;
        return mcp_err("Refusing to %s pid %lu", suspend ? "suspend" : "resume", (unsigned long)pid);
    }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_SUSPEND_RESUME, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_SUSPEND_RESUME)", st); }
    st = suspend ? NtSuspendProcess(h) : NtResumeProcess(h);
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error(suspend ? "NtSuspendProcess" : "NtResumeProcess", st); }
    return mcp_ok("%s pid %lu", suspend ? "Suspended" : "Resumed", (unsigned long)pid);
}
static cJSON *tool_suspend_process(const cJSON *args, int *isError) { return suspend_resume(args, 1, isError); }
static cJSON *tool_resume_process(const cJSON *args, int *isError) { return suspend_resume(args, 0, isError); }

static cJSON *tool_set_process_priority(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    const char *prio = mcp_arg_str(args, "priority", NULL);
    ULONG pc;
    if (!priority_class_from_name(prio, &pc))
    {
        *isError = 1;
        return mcp_err_hint("Valid values: idle, below_normal, normal, above_normal, high, realtime.", "Missing or invalid 'priority'");
    }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_SET_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_SET_INFORMATION)", st); }
    PROCESS_PRIORITY_CLASS ppc;
    ppc.Foreground = FALSE;
    ppc.PriorityClass = (UCHAR)pc;
    st = NtSetInformationProcess(h, ProcessPriorityClass, &ppc, sizeof(ppc));
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtSetInformationProcess(PriorityClass)", st); }
    return mcp_ok("Set pid %lu priority to %s", (unsigned long)pid, prio);
}

static cJSON *tool_set_process_affinity(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int found = 0;
    unsigned long long mask = mcp_arg_u64(args, "affinity_mask", 0, &found);
    if (!found || mask == 0)
    {
        *isError = 1;
        return mcp_err_hint("Bitmask of allowed logical CPUs, e.g. 0x3 for CPUs 0 and 1 (number or hex string).", "Missing or zero 'affinity_mask'");
    }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_SET_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_SET_INFORMATION)", st); }
    KAFFINITY aff = (KAFFINITY)mask;
    st = NtSetInformationProcess(h, ProcessAffinityMask, &aff, sizeof(aff));
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtSetInformationProcess(AffinityMask)", st); }
    return mcp_ok("Set pid %lu affinity to 0x%llX", (unsigned long)pid, mask);
}

static cJSON *tool_empty_working_set(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_SET_QUOTA)", st); }
    QUOTA_LIMITS_EX ql;
    memset(&ql, 0, sizeof(ql));
    ql.MinimumWorkingSetSize = (SIZE_T)-1;
    ql.MaximumWorkingSetSize = (SIZE_T)-1;
    st = NtSetInformationProcess(h, ProcessQuotaLimits, &ql, sizeof(ql));
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtSetInformationProcess(QuotaLimits)", st); }
    return mcp_ok("Emptied working set of pid %lu", (unsigned long)pid);
}

static cJSON *tool_set_process_critical(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    int critical = mcp_arg_bool(args, "critical", 1);
    ntu_enable_privilege(SE_DEBUG_NAME);
    NTSTATUS st;
    HANDLE h = ntu_open_process(pid, PROCESS_SET_INFORMATION, &st);
    if (!h) { *isError = 1; return ntu_status_error("NtOpenProcess(PROCESS_SET_INFORMATION)", st); }
    ULONG v = critical ? 1 : 0;
    st = NtSetInformationProcess(h, ProcessBreakOnTermination, &v, sizeof(v));
    NtClose(h);
    if (!NT_SUCCESS(st)) { *isError = 1; return ntu_status_error("NtSetInformationProcess(BreakOnTermination)", st); }
    return mcp_ok("pid %lu critical flag is now %s", (unsigned long)pid, critical ? "SET (terminating it will bugcheck Windows)" : "cleared");
}

static cJSON *tool_create_process_dump(const cJSON *args, int *isError)
{
    DWORD pid; cJSON *err;
    if (!require_pid(args, &pid, &err)) { *isError = 1; return err; }
    const char *outPath = mcp_arg_str(args, "output_path", NULL);
    const char *type = mcp_arg_str(args, "dump_type", "mini");

    char path[MAX_PATH];
    if (outPath && outPath[0])
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s", outPath);
    else
    {
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        char now[32];
        ntu_now_iso(now, sizeof(now));
        for (char *c = now; *c; c++) if (*c == ':') *c = '-';
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s%lu_%s.dmp", tmp, (unsigned long)pid, now);
    }

    MINIDUMP_TYPE mt;
    if (_stricmp(type, "full") == 0)
        mt = MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo;
    else if (_stricmp(type, "normal") == 0)
        mt = MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory;
    else
        mt = MiniDumpNormal | MiniDumpWithThreadInfo;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pid);
    if (!h) { *isError = 1; return ntu_win_error("OpenProcess", GetLastError()); }
    PWSTR wpath = ntu_u2w(path);
    HANDLE file = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (file == INVALID_HANDLE_VALUE)
    {
        DWORD e = GetLastError();
        CloseHandle(h);
        *isError = 1;
        return ntu_win_error("CreateFile(dump)", e);
    }
    BOOL ok = MiniDumpWriteDump(h, pid, file, mt, NULL, NULL, NULL);
    DWORD e = ok ? 0 : GetLastError();
    LARGE_INTEGER size = {0};
    GetFileSizeEx(file, &size);
    CloseHandle(file);
    CloseHandle(h);
    if (!ok)
    {
        *isError = 1;
        return ntu_win_error("MiniDumpWriteDump", e);
    }
    cJSON *o = mcp_ok("Wrote %s dump for pid %lu", type, (unsigned long)pid);
    cJSON_AddStringToObject(o, "path", path);
    ntu_add_bytes(o, "size", (unsigned long long)size.QuadPart);
    return o;
}

/* ===========================================================================
 * Registration
 * ========================================================================= */
#define PID_PROP "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Process id (decimal number, or a decimal/hex string such as \\\"0x1a4\\\"). Find it with list_processes.\"}"
#define CONFIRM_PROP "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true. This tool changes the system; the call is refused without explicit confirmation.\"}"

static const Tool g_process_tools[] = {
    { "list_processes", "List processes",
      "Enumerate running processes (the System Informer 'Processes' tab). Returns pid, name, parent pid, "
      "session, thread/handle counts, working set, private bytes, start time, CPU times, and optionally "
      "a measured CPU % (two samples) and image path/user/integrity. Use name_filter to narrow by name "
      "(case-insensitive substring), sort_by to rank (e.g. 'cpu' or 'memory' to find hogs) and limit to "
      "keep the output small. For one process's full detail use process_details.",
      "{\"type\":\"object\",\"properties\":{"
      "\"sort_by\":{\"type\":\"string\",\"enum\":[\"pid\",\"name\",\"cpu\",\"memory\",\"private\",\"threads\",\"handles\",\"start_time\"],\"default\":\"pid\",\"description\":\"Sort key. 'cpu' triggers a CPU measurement over sample_ms.\"},"
      "\"name_filter\":{\"type\":\"string\",\"description\":\"Case-insensitive substring to match against the image name, e.g. \\\"chrome\\\".\"},"
      "\"limit\":{\"type\":\"integer\",\"description\":\"Return at most this many processes (0 = all).\",\"default\":0},"
      "\"include_paths\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Also open each process to add imagePath, user, integrity, priorityClass, protection. Slower.\"},"
      "\"include_cpu\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Measure per-process CPU %% even when not sorting by cpu.\"},"
      "\"sample_ms\":{\"type\":\"integer\",\"default\":500,\"description\":\"CPU sampling window in ms (100-5000).\"}"
      "},\"additionalProperties\":false}", 0, tool_list_processes },

    { "process_tree", "Process tree",
      "Parent/child hierarchy of all processes (or of one subtree when root_pid is given). Each node has "
      "pid, name, workingSet and children[]. Guards against PID reuse (a 'parent' created after its child "
      "is treated as unrelated). Use this to understand who launched what.",
      "{\"type\":\"object\",\"properties\":{"
      "\"root_pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Only return the subtree rooted at this pid.\"}"
      "},\"additionalProperties\":false}", 0, tool_process_tree },

    { "process_details", "Process details",
      "Everything the System Informer 'General'/'Statistics' property pages show for one process: "
      "image path, command line, current directory, parent (name+pid), user/SID/integrity/elevation, "
      "priority class, affinity, 32/64-bit, protection (PPL), critical flag, debugger attached, DEP, job "
      "membership, memory counters (working set, private, peak, pools, page faults), I/O counters, GDI/USER "
      "handle counts, and timings. Use after list_processes to drill into one pid.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "},\"required\":[\"pid\"],\"additionalProperties\":false}",
      0, tool_process_details },

    { "process_token", "Process token",
      "The System Informer 'Token' page: user, owner, integrity level, elevation type, token type, session, "
      "app-container/UIAccess/virtualization flags, all group SIDs with attributes, and all privileges with "
      "their enabled/disabled state. Use to answer 'what can this process do?' or to check SeDebugPrivilege etc.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "},\"required\":[\"pid\"],\"additionalProperties\":false}",
      0, tool_process_token },

    { "launch_process", "Launch process",
      "Start a new process with the same token as this server (like System Informer's 'Run...' / Ctrl+R). "
      "Give the full command line (program plus arguments, quote paths with spaces). Returns the new pid so "
      "you can inspect or control it. Window can be normal/minimized/maximized/hidden. To start elevated use "
      "launch_process_elevated. Example: {\"command_line\":\"notepad.exe\"}.",
      "{\"type\":\"object\",\"properties\":{"
      "\"command_line\":{\"type\":\"string\",\"description\":\"Program and arguments, e.g. \\\"notepad.exe C:\\\\\\\\temp\\\\\\\\a.txt\\\" or \\\"\\\\\\\"C:\\\\\\\\Program Files\\\\\\\\App\\\\\\\\app.exe\\\\\\\" --flag\\\".\"},"
      "\"working_directory\":{\"type\":\"string\",\"description\":\"Optional start directory.\"},"
      "\"window\":{\"type\":\"string\",\"enum\":[\"normal\",\"minimized\",\"maximized\",\"hidden\"],\"default\":\"normal\",\"description\":\"Initial window state.\"}"
      "},\"required\":[\"command_line\"],\"additionalProperties\":false}", 0, tool_launch_process },

    { "launch_process_elevated", "Launch process elevated",
      "Start a process as Administrator via the standard Windows UAC consent prompt (System Informer 'Run as "
      "administrator'). The user must approve the prompt on screen; if they decline you get a clear error. "
      "Same arguments as launch_process.",
      "{\"type\":\"object\",\"properties\":{"
      "\"command_line\":{\"type\":\"string\",\"description\":\"Program and arguments.\"},"
      "\"working_directory\":{\"type\":\"string\",\"description\":\"Optional start directory.\"},"
      "\"window\":{\"type\":\"string\",\"enum\":[\"normal\",\"minimized\",\"maximized\",\"hidden\"],\"default\":\"normal\"}"
      "},\"required\":[\"command_line\"],\"additionalProperties\":false}", 0, tool_launch_process_elevated },

    { "terminate_process", "Terminate process",
      "GUARDED (confirm=true required). Forcibly end a process (System Informer 'Terminate' / Del). The "
      "process gets no chance to save; prefer closing its window (window_action close) for a graceful exit. "
      "Refuses system pids 0/4, this server, and processes marked critical unless allow_critical=true "
      "(killing a critical process crashes Windows with a bugcheck).",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"exit_code\":{\"type\":\"integer\",\"default\":1,\"description\":\"Exit code to give the process.\"},"
      "\"allow_critical\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Allow terminating a process flagged critical. THIS WILL BUGCHECK WINDOWS.\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}", 1, tool_terminate_process },

    { "terminate_process_tree", "Terminate process tree",
      "GUARDED (confirm=true required). Terminate a process and every descendant (System Informer "
      "'Terminate tree' / Shift+Del). Children are killed first. Returns the pids terminated and any that "
      "failed with their NTSTATUS.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}",
      1, tool_terminate_process_tree },

    { "suspend_process", "Suspend process",
      "GUARDED (confirm=true required). Freeze every thread of a process (System Informer 'Suspend'). The "
      "process keeps its memory and handles but makes no progress until resume_process. Useful to pause a "
      "runaway or suspicious process for inspection without killing it.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}",
      1, tool_suspend_process },

    { "resume_process", "Resume process",
      "GUARDED (confirm=true required). Resume all threads of a process previously frozen with "
      "suspend_process (System Informer 'Resume').",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}",
      1, tool_resume_process },

    { "set_process_priority", "Set process priority",
      "GUARDED (confirm=true required). Change a process's priority class (System Informer 'Priority' "
      "submenu). 'realtime' can starve the system; use with care.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"priority\":{\"type\":\"string\",\"enum\":[\"idle\",\"below_normal\",\"normal\",\"above_normal\",\"high\",\"realtime\"],\"description\":\"New priority class.\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"priority\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_process_priority },

    { "set_process_affinity", "Set process affinity",
      "GUARDED (confirm=true required). Restrict which logical CPUs a process may run on (System Informer "
      "'Affinity'). affinity_mask is a bitmask: bit N = CPU N, e.g. 0x3 = CPUs 0-1, 0xF = CPUs 0-3.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"affinity_mask\":{\"type\":[\"integer\",\"string\"],\"description\":\"CPU bitmask as number or hex string, e.g. \\\"0xF\\\".\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"affinity_mask\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_process_affinity },

    { "empty_working_set", "Empty working set",
      "GUARDED (confirm=true required). Trim a process's working set to the minimum, pushing its pages out "
      "of RAM (System Informer 'Miscellaneous > Reduce working set'). Harmless but the process will page-fault "
      "its memory back in as it runs. Useful to reclaim RAM temporarily.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP "," CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}",
      1, tool_empty_working_set },

    { "set_process_critical", "Set/clear critical flag",
      "GUARDED (confirm=true required). Set or clear the 'critical process' flag (System Informer "
      "'Miscellaneous > Critical'). A critical process bugchecks (crashes) Windows when it exits. Setting "
      "this on the wrong process is dangerous; clearing it is how you make a critical process safely "
      "terminable. Requires SeDebugPrivilege (elevated).",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"critical\":{\"type\":\"boolean\",\"default\":true,\"description\":\"true = mark critical, false = clear the flag.\"},"
      CONFIRM_PROP "},\"required\":[\"pid\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_process_critical },

    { "create_process_dump", "Create process dump",
      "Write a minidump of a process to disk (System Informer 'Create dump file...'), for later analysis in "
      "WinDbg/Visual Studio. dump_type: 'mini' (stacks only, small), 'normal' (plus data segments, handles, "
      "referenced memory) or 'full' (all memory; can be gigabytes). Defaults to %TEMP%\\<pid>_<time>.dmp.",
      "{\"type\":\"object\",\"properties\":{" PID_PROP ","
      "\"output_path\":{\"type\":\"string\",\"description\":\"Destination .dmp path. Default: %TEMP%\\\\<pid>_<timestamp>.dmp\"},"
      "\"dump_type\":{\"type\":\"string\",\"enum\":[\"mini\",\"normal\",\"full\"],\"default\":\"mini\"}"
      "},\"required\":[\"pid\"],\"additionalProperties\":false}", 0, tool_create_process_dump },
};

void register_process_tools(void)
{
    for (size_t i = 0; i < sizeof(g_process_tools) / sizeof(g_process_tools[0]); i++)
        mcp_register_tool(&g_process_tools[i]);
}