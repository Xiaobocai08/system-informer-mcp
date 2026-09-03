/* Shared process-snapshot helpers (SystemProcessInformation). */
#ifndef SIMCP_PROCSNAP_H
#define SIMCP_PROCSNAP_H

#include "ntutil.h"

typedef struct ProcSnap {
    PVOID buffer;
} ProcSnap;

NTSTATUS snap_take(ProcSnap *s);
void     snap_free(ProcSnap *s);
PSYSTEM_PROCESS_INFORMATION snap_find(const ProcSnap *s, DWORD pid);

#define SNAP_FOREACH(s, p) \
    for (PSYSTEM_PROCESS_INFORMATION p = (PSYSTEM_PROCESS_INFORMATION)(s)->buffer; p; \
         p = p->NextEntryOffset ? (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)p + p->NextEntryOffset) : NULL)

/* UTF-8 image name, with "System"/"System Idle Process" for pid 4/0. */
void proc_name_utf8(PSYSTEM_PROCESS_INFORMATION p, char *out, size_t cap);

/* Priority-class <-> name. */
const char *priority_class_name(ULONG pc);
int         priority_class_from_name(const char *s, ULONG *out);

/* Thread state / wait reason names. */
const char *thread_state_name(ULONG state);
const char *wait_reason_name(ULONG reason);

/* Adds user/userSid/integrity/elevated/elevationType from a process handle. */
void add_token_summary(cJSON *o, HANDLE process);

#endif
