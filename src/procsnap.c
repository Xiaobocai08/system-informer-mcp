#include "procsnap.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

NTSTATUS snap_take(ProcSnap *s)
{
    s->buffer = NULL;
    return ntu_query_system(SystemProcessInformation, &s->buffer, NULL);
}

void snap_free(ProcSnap *s)
{
    free(s->buffer);
    s->buffer = NULL;
}

PSYSTEM_PROCESS_INFORMATION snap_find(const ProcSnap *s, DWORD pid)
{
    SNAP_FOREACH(s, p)
    {
        if ((DWORD)(ULONG_PTR)p->UniqueProcessId == pid)
            return p;
    }
    return NULL;
}

void proc_name_utf8(PSYSTEM_PROCESS_INFORMATION p, char *out, size_t cap)
{
    DWORD pid = (DWORD)(ULONG_PTR)p->UniqueProcessId;
    if (p->ImageName.Buffer && p->ImageName.Length)
    {
        char *u = ntu_w2u(p->ImageName.Buffer, (int)(p->ImageName.Length / sizeof(WCHAR)));
        if (u)
        {
            _snprintf_s(out, cap, _TRUNCATE, "%s", u);
            free(u);
            return;
        }
    }
    if (pid == 0)
        _snprintf_s(out, cap, _TRUNCATE, "System Idle Process");
    else if (pid == 4)
        _snprintf_s(out, cap, _TRUNCATE, "System");
    else
        _snprintf_s(out, cap, _TRUNCATE, "(unknown)");
}

const char *priority_class_name(ULONG pc)
{
    switch (pc)
    {
    case PROCESS_PRIORITY_CLASS_IDLE: return "idle";
    case PROCESS_PRIORITY_CLASS_NORMAL: return "normal";
    case PROCESS_PRIORITY_CLASS_HIGH: return "high";
    case PROCESS_PRIORITY_CLASS_REALTIME: return "realtime";
    case PROCESS_PRIORITY_CLASS_BELOW_NORMAL: return "below_normal";
    case PROCESS_PRIORITY_CLASS_ABOVE_NORMAL: return "above_normal";
    default: return "unknown";
    }
}

int priority_class_from_name(const char *s, ULONG *out)
{
    if (!s) return 0;
    if (_stricmp(s, "idle") == 0) { *out = PROCESS_PRIORITY_CLASS_IDLE; return 1; }
    if (_stricmp(s, "below_normal") == 0) { *out = PROCESS_PRIORITY_CLASS_BELOW_NORMAL; return 1; }
    if (_stricmp(s, "normal") == 0) { *out = PROCESS_PRIORITY_CLASS_NORMAL; return 1; }
    if (_stricmp(s, "above_normal") == 0) { *out = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL; return 1; }
    if (_stricmp(s, "high") == 0) { *out = PROCESS_PRIORITY_CLASS_HIGH; return 1; }
    if (_stricmp(s, "realtime") == 0) { *out = PROCESS_PRIORITY_CLASS_REALTIME; return 1; }
    return 0;
}

const char *thread_state_name(ULONG state)
{
    static const char *names[] = {
        "Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting",
        "Transition", "DeferredReady", "GateWait", "WaitingForProcessInSwap"
    };
    if (state < sizeof(names) / sizeof(names[0]))
        return names[state];
    return "Unknown";
}

const char *wait_reason_name(ULONG reason)
{
    static const char *names[] = {
        "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended",
        "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn", "WrPoolAllocation",
        "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue",
        "WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous",
        "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack",
        "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt",
        "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown",
        "WrAlertByThreadId", "WrDeferredPreempt", "WrPhysicalFault", "WrIoRing", "WrMdlCache"
    };
    if (reason < sizeof(names) / sizeof(names[0]))
        return names[reason];
    return "Unknown";
}

static const char *integrity_name(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return "Protected";
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID) return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID) return "Low";
    return "Untrusted";
}

void add_token_summary(cJSON *o, HANDLE process)
{
    HANDLE token;
    if (!NT_SUCCESS(NtOpenProcessToken(process, TOKEN_QUERY, &token)))
        return;

    UCHAR buf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
    ULONG len = 0;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenUser, buf, sizeof(buf), &len)))
    {
        PTOKEN_USER tu = (PTOKEN_USER)buf;
        char *acct = ntu_sid_account(tu->User.Sid);
        char *sid = ntu_sid_to_string(tu->User.Sid);
        if (acct) { cJSON_AddStringToObject(o, "user", acct); free(acct); }
        if (sid) { cJSON_AddStringToObject(o, "userSid", sid); free(sid); }
    }

    UCHAR ilBuf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_MANDATORY_LABEL)];
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenIntegrityLevel, ilBuf, sizeof(ilBuf), &len)))
    {
        PTOKEN_MANDATORY_LABEL tml = (PTOKEN_MANDATORY_LABEL)ilBuf;
        PUCHAR count = RtlSubAuthorityCountSid(tml->Label.Sid);
        if (count && *count > 0)
        {
            DWORD rid = *RtlSubAuthoritySid(tml->Label.Sid, *count - 1);
            cJSON_AddStringToObject(o, "integrity", integrity_name(rid));
        }
    }

    TOKEN_ELEVATION elev;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenElevation, &elev, sizeof(elev), &len)))
        cJSON_AddBoolToObject(o, "elevated", elev.TokenIsElevated ? 1 : 0);

    TOKEN_ELEVATION_TYPE et;
    if (NT_SUCCESS(NtQueryInformationToken(token, TokenElevationType, &et, sizeof(et), &len)))
    {
        const char *s = et == TokenElevationTypeDefault ? "default" :
                        et == TokenElevationTypeFull ? "full" :
                        et == TokenElevationTypeLimited ? "limited" : "unknown";
        cJSON_AddStringToObject(o, "elevationType", s);
    }

    NtClose(token);
}
