/*
 * System Informer MCP server - core protocol / tool-registry definitions.
 *
 * This header is intentionally free of <windows.h> / phnt so it can be included
 * by pure protocol code. Tool implementations include phnt themselves (before
 * including this header is fine; order does not matter here).
 */
#ifndef SIMCP_MCP_H
#define SIMCP_MCP_H

#include <stddef.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A tool handler receives the "arguments" object from tools/call (may be NULL)
 * and returns a newly allocated cJSON value (object or array) that becomes the
 * tool result. On failure the handler should set *isError = 1 and return an
 * object describing the problem (see mcp_err()). Ownership of the returned
 * value transfers to the caller.
 */
typedef cJSON *(*tool_fn)(const cJSON *args, int *isError);

typedef struct Tool {
    const char *name;         /* unique tool id, e.g. "list_processes"        */
    const char *title;        /* short human title                            */
    const char *description;  /* rich description: when + how to use it       */
    const char *inputSchema;  /* JSON Schema (draft-07) as a string           */
    int         destructive;  /* 1 = mutating/irreversible; needs confirm=true */
    tool_fn     fn;
} Tool;

/* ---- Tool registry -------------------------------------------------------- */
void          mcp_register_tool(const Tool *t);
const Tool  **mcp_tools(size_t *count);
const Tool   *mcp_find_tool(const char *name);

/* Registers every tool group. Implemented in registry.c. */
void mcp_register_all_tools(void);

/* ---- Result / error helpers (defined in mcp.c) ---------------------------- */

/* Build an error object: { "error": <msg>, "hint": <optional> }. */
cJSON *mcp_err(const char *fmt, ...);
cJSON *mcp_err_hint(const char *hint, const char *fmt, ...);

/* Build a simple status object: { "status": "ok", "message": <msg> }. */
cJSON *mcp_ok(const char *fmt, ...);

/* ---- Argument helpers ----------------------------------------------------- */
/* All tolerate args==NULL and missing keys. Numbers accept JSON number or a
 * decimal/hex ("0x..") string, which is convenient for PIDs/addresses. */
int          mcp_arg_present(const cJSON *args, const char *key);
unsigned long long mcp_arg_u64(const cJSON *args, const char *key, unsigned long long def, int *found);
long long    mcp_arg_i64(const cJSON *args, const char *key, long long def);
int          mcp_arg_bool(const cJSON *args, const char *key, int def);
/* Returns a pointer into the cJSON tree (do not free); NULL if absent. */
const char  *mcp_arg_str(const cJSON *args, const char *key, const char *def);

/* ---- Prompts (defined in prompts.c) --------------------------------------- */
cJSON *mcp_prompts_list(void);                       /* -> array for prompts/list */
cJSON *mcp_prompt_get(const char *name, const cJSON *args); /* -> messages object or NULL */

/* The long-form "instructions" string returned from initialize. */
const char *mcp_instructions(void);

/* Server identity. */
#define SIMCP_SERVER_NAME    "system-informer"
#define SIMCP_SERVER_VERSION "1.0.0"

#ifdef __cplusplus
}
#endif

#endif /* SIMCP_MCP_H */
