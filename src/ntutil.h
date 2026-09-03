/*
 * NT / Win32 helper layer shared by the tool implementations.
 *
 * Include this FIRST in any tool file: it pulls in System Informer's phnt
 * headers in the correct order (phnt_windows.h before phnt.h) before anything
 * else can drag in <windows.h>.
 */
#ifndef SIMCP_NTUTIL_H
#define SIMCP_NTUTIL_H

#include <phnt_windows.h>
#include <phnt.h>

#include "cJSON.h"

/* ---- time ----------------------------------------------------------------- */
/* Format a 100ns-since-1601 timestamp (FILETIME/LARGE_INTEGER epoch) as UTC
 * ISO-8601, e.g. "2026-09-03T07:15:00Z". out must hold >= 32 bytes. If the
 * value is 0 the buffer is set to an empty string. */
void   ntu_time_to_iso(LONG64 timestamp100ns, char *out, size_t cap);
void   ntu_now_iso(char *out, size_t cap);

/* ---- strings -------------------------------------------------------------- */
/* Convert UTF-16 -> UTF-8 (malloc, caller frees). cch = character count, or -1
 * for null-terminated. Returns NULL for empty/NULL input. */
char  *ntu_w2u(PCWSTR w, int cch);
/* Convert UTF-8 -> UTF-16 (malloc, caller frees). */
PWSTR  ntu_u2w(const char *s);
/* Add a UTF-16 string to a cJSON object as UTF-8 (adds JSON null if w==NULL). */
void   ntu_add_w(cJSON *obj, const char *key, PCWSTR w);
void   ntu_add_wn(cJSON *obj, const char *key, PCWSTR w, int cch);
/* Add a UNICODE_STRING. */
void   ntu_add_us(cJSON *obj, const char *key, const UNICODE_STRING *us);

/* ---- sizes ---------------------------------------------------------------- */
/* Adds <key> (raw bytes as number) and <key>_pretty ("12.3 MB"). */
void   ntu_add_bytes(cJSON *obj, const char *key, unsigned long long bytes);
void   ntu_bytes_pretty(unsigned long long bytes, char *out, size_t cap);

/* ---- errors --------------------------------------------------------------- */
const char *ntu_status_string(NTSTATUS status, char *buf, size_t cap);
/* Build an { "error": ..., "status": "0x...", "detail": ... } object. */
cJSON *ntu_status_error(const char *where, NTSTATUS status);
cJSON *ntu_win_error(const char *where, DWORD err);

/* ---- processes / threads -------------------------------------------------- */
HANDLE ntu_open_process(DWORD pid, ACCESS_MASK access, NTSTATUS *status);
HANDLE ntu_open_thread(DWORD tid, ACCESS_MASK access, NTSTATUS *status);
char  *ntu_process_image_path(HANDLE process);   /* win32 path, UTF-8, malloc */
char  *ntu_process_command_line(HANDLE process); /* UTF-8, malloc             */

/* ---- SIDs ----------------------------------------------------------------- */
char  *ntu_sid_to_string(PSID sid);   /* "S-1-5-.." malloc */
char  *ntu_sid_account(PSID sid);     /* "DOMAIN\\User" malloc or NULL */

/* ---- privileges / token --------------------------------------------------- */
int    ntu_enable_privilege(PCWSTR privilegeName); /* 1 on success */
int    ntu_current_is_elevated(void);

/* ---- generic system-information query ------------------------------------- */
/* Allocates *buffer via malloc (caller frees) and fills it with the requested
 * class, retrying on STATUS_INFO_LENGTH_MISMATCH. */
NTSTATUS ntu_query_system(SYSTEM_INFORMATION_CLASS cls, PVOID *buffer, ULONG *length);

#endif /* SIMCP_NTUTIL_H */
