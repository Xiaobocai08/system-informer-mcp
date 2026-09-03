#include "mcp.h"

#include <string.h>
#include <stdio.h>

/* ---------------------------------------------------------------------------
 * initialize.instructions
 *
 * This is the single most important piece of "don't make the AI guess" text.
 * It is delivered to the model once at connection time and explains the whole
 * server: what it can do, the privilege model, identifier/units conventions,
 * the safety guard, and how to discover everything else.
 * ------------------------------------------------------------------------- */
const char *mcp_instructions(void)
{
    return
"System Informer MCP\n"
"===================\n"
"This server exposes the capabilities of System Informer (formerly Process Hacker) "
"as structured tools. It is built directly on System Informer's own `phnt` NT-API "
"headers and calls the same native Windows APIs the System Informer GUI uses "
"(NtQuerySystemInformation, NtQueryInformationProcess/Thread, the Service Control "
"Manager, IP Helper, WinVerifyTrust, ...). Every data view and action a human can "
"reach through the System Informer GUI has a corresponding tool here, and results "
"come back as JSON instead of GUI tables.\n"
"\n"
"WHEN TO USE THIS SERVER\n"
"- Inspecting or troubleshooting the live Windows system: processes, threads, loaded "
"modules/DLLs, handles, memory, tokens/privileges, services, drivers, network "
"connections, and top-level windows.\n"
"- Acting on the system: start/terminate/suspend/resume processes and threads, change "
"priority/affinity, empty working sets, write minidumps, control/create/delete "
"services, close handles, read/write process memory, and close/minimise/restore "
"windows.\n"
"- Handing off to the real System Informer GUI for interactive/graphical views.\n"
"\n"
"DISCOVERY\n"
"- Call tools/list to see all tools; each has a detailed description and a JSON Schema "
"with per-argument documentation and enums. Do not guess arguments - read the schema.\n"
"- Call prompts/list for ready-made investigation workflows (high CPU, suspicious "
"process triage, what-locks-this-file, what-owns-this-port, etc.).\n"
"- Call the `server_status` tool first in a session: it reports the server version, "
"whether it is running elevated, whether the System Informer application/driver are "
"present, and therefore what coverage you can expect.\n"
"\n"
"IDENTIFIERS & UNITS\n"
"- Process IDs (pid) and thread IDs (tid) are integers. You may pass them as numbers "
"or as decimal/hex strings (\"0x1a4\").\n"
"- Memory addresses and sizes may be given as numbers or hex strings; addresses are "
"returned as hex strings like \"0x7ff6...\".\n"
"- Byte sizes are returned both raw (`x`) and human-readable (`x_pretty`).\n"
"- Timestamps are UTC ISO-8601 (\"2026-09-03T07:15:00Z\").\n"
"\n"
"PRIVILEGES (this determines what you can see and do)\n"
"- Windows - not this server - decides visibility. Run the server elevated (as "
"Administrator) for full coverage. Unelevated you get your own processes in full and "
"limited detail for others; some kernel addresses read back as 0.\n"
"- Protected processes (PPL, antimalware, some system processes) additionally require "
"System Informer's kernel driver (KSystemInformer). If a call returns Access Denied, "
"that is usually the reason - report it; do not retry in a loop.\n"
"\n"
"SAFETY\n"
"- Tools that mutate the system or are irreversible are GUARDED: they refuse to run "
"unless you pass \"confirm\": true in the arguments. This includes terminate_process, "
"terminate_process_tree, suspend/resume, set_process_priority/affinity, "
"empty_working_set, write_process_memory, close_handle, terminate_thread, "
"control_service, set_service_start_type, create_service, delete_service, and "
"window_action. Each such tool says so in its description. Setting confirm=true is "
"how you deliberately proceed.\n"
"- Be especially careful terminating system-critical processes; doing so can bugcheck "
"(crash) Windows. When unsure, inspect first.\n"
"\n"
"GOOD PRACTICE\n"
"- Prefer the most specific tool (e.g. `port_owner` over scanning all connections).\n"
"- Inspect before you act: read process_details / handles / modules before terminating "
"or writing memory.\n"
"- If a tool returns an object with an \"error\" field, read its \"hint\"; it usually "
"tells you exactly what to change (e.g. elevate).\n";
}

/* ---------------------------------------------------------------------------
 * Prompts
 * ------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    const char *description;
    const char *argName;   /* single optional argument, or NULL */
    const char *argDesc;
    int         argRequired;
} PromptDef;

static const PromptDef g_prompts[] = {
    { "diagnose_high_cpu",
      "Find and explain which processes/threads are driving CPU usage right now, and suggest safe next steps.",
      NULL, NULL, 0 },
    { "triage_suspicious_process",
      "Systematically assess whether a process is malicious: signature, path, command line, parent, modules, network, handles.",
      "pid", "PID of the process to triage.", 1 },
    { "inspect_process",
      "Produce a thorough report on a single process (details, modules, threads, token, memory summary).",
      "pid", "PID of the process to inspect.", 1 },
    { "what_locks_file",
      "Determine which process holds a handle to a given file/DLL path so it can be unlocked.",
      "name", "Full or partial file path/name to search for among open handles.", 1 },
    { "what_owns_port",
      "Identify which process is listening on or connected via a given TCP/UDP port.",
      "port", "Port number to look up.", 1 },
};

static const size_t g_prompt_count = sizeof(g_prompts) / sizeof(g_prompts[0]);

cJSON *mcp_prompts_list(void)
{
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < g_prompt_count; i++)
    {
        const PromptDef *p = &g_prompts[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", p->name);
        cJSON_AddStringToObject(item, "description", p->description);
        cJSON *args = cJSON_CreateArray();
        if (p->argName)
        {
            cJSON *a = cJSON_CreateObject();
            cJSON_AddStringToObject(a, "name", p->argName);
            cJSON_AddStringToObject(a, "description", p->argDesc);
            cJSON_AddBoolToObject(a, "required", p->argRequired);
            cJSON_AddItemToArray(args, a);
        }
        cJSON_AddItemToObject(item, "arguments", args);
        cJSON_AddItemToArray(arr, item);
    }
    return arr;
}

static cJSON *make_prompt_result(const char *description, const char *userText)
{
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "description", description);
    cJSON *messages = cJSON_CreateArray();
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "role", "user");
    cJSON *content = cJSON_CreateObject();
    cJSON_AddStringToObject(content, "type", "text");
    cJSON_AddStringToObject(content, "text", userText);
    cJSON_AddItemToObject(msg, "content", content);
    cJSON_AddItemToArray(messages, msg);
    cJSON_AddItemToObject(result, "messages", messages);
    return result;
}

cJSON *mcp_prompt_get(const char *name, const cJSON *args)
{
    char text[2048];
    const char *arg = NULL;
    if (args)
    {
        /* prompt arguments are always strings per MCP */
        const cJSON *first = NULL;
        for (size_t i = 0; i < g_prompt_count; i++)
        {
            if (strcmp(g_prompts[i].name, name) == 0 && g_prompts[i].argName)
            {
                first = cJSON_GetObjectItemCaseSensitive(args, g_prompts[i].argName);
                break;
            }
        }
        if (first && cJSON_IsString(first))
            arg = first->valuestring;
    }

    if (strcmp(name, "diagnose_high_cpu") == 0)
    {
        _snprintf_s(text, sizeof(text), _TRUNCATE,
            "Diagnose what is using the CPU on this Windows machine.\n"
            "1. Call list_processes with sort_by=\"cpu\" and limit=15.\n"
            "2. For the top offenders, call process_threads to see which threads are hot and "
            "process_details for context (image path, command line, user, signed?).\n"
            "3. Explain the likely cause in plain language and suggest safe actions "
            "(e.g. whether it is expected). Only suspend/terminate with confirm=true and after explaining the risk.");
        return make_prompt_result("Diagnose high CPU usage", text);
    }
    if (strcmp(name, "triage_suspicious_process") == 0)
    {
        _snprintf_s(text, sizeof(text), _TRUNCATE,
            "Triage process PID %s for signs of compromise. Do NOT terminate anything unless explicitly asked.\n"
            "1. process_details %s - note image path, command line, parent, user, integrity, start time.\n"
            "2. verify_file_signature on its image path - is it validly signed and by whom?\n"
            "3. process_modules - look for unsigned/oddly-located DLLs.\n"
            "4. network_connections filtered to this pid - unexpected remote endpoints?\n"
            "5. list_handles / find_handles_by_name for suspicious files, pipes, or other processes.\n"
            "6. Summarise risk (benign / suspicious / likely-malicious) with concrete evidence.",
            arg ? arg : "<pid>", arg ? arg : "<pid>");
        return make_prompt_result("Triage a possibly-malicious process", text);
    }
    if (strcmp(name, "inspect_process") == 0)
    {
        _snprintf_s(text, sizeof(text), _TRUNCATE,
            "Produce a thorough report on process PID %s: call process_details, process_modules, "
            "process_threads, process_token, and process_memory_summary, then synthesise a concise summary.",
            arg ? arg : "<pid>");
        return make_prompt_result("Inspect a process in depth", text);
    }
    if (strcmp(name, "what_locks_file") == 0)
    {
        _snprintf_s(text, sizeof(text), _TRUNCATE,
            "Find which process is locking \"%s\".\n"
            "Call find_handles_by_name with name=\"%s\". For each match, report the owning process "
            "(pid + image path) and the handle. If nothing is found, note that the lock may be a memory-mapped "
            "section rather than a file handle.",
            arg ? arg : "<path>", arg ? arg : "<path>");
        return make_prompt_result("Find what locks a file", text);
    }
    if (strcmp(name, "what_owns_port") == 0)
    {
        _snprintf_s(text, sizeof(text), _TRUNCATE,
            "Identify what is using port %s. Call port_owner with port=%s, then process_details on the owning "
            "pid to describe the program.",
            arg ? arg : "<port>", arg ? arg : "<port>");
        return make_prompt_result("Find what owns a port", text);
    }
    return NULL;
}
