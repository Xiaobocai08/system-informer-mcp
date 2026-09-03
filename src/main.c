/*
 * System Informer MCP server - entry point.
 *
 * Speaks the Model Context Protocol over stdio: newline-delimited JSON-RPC 2.0
 * messages on stdin/stdout. All diagnostics go to stderr so stdout stays clean.
 */
#include <windows.h>   /* for SEH constants only; this TU does not include phnt */
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcp.h"

/* Protocol version we implement (we echo the client's if it sends one). */
#define SIMCP_PROTOCOL_VERSION "2024-11-05"

/* ---- low level IO --------------------------------------------------------- */
static void write_message(cJSON *msg)
{
    char *s = cJSON_PrintUnformatted(msg);
    if (!s)
        return;
    fwrite(s, 1, strlen(s), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    cJSON_free(s);
}

/* Reads one newline-delimited message. Returns malloc'd string (no newline) or
 * NULL on EOF with no data. */
static char *read_line(void)
{
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf)
        return NULL;
    int c;
    int any = 0;
    while ((c = fgetc(stdin)) != EOF)
    {
        any = 1;
        if (c == '\n')
            break;
        if (c == '\r')
            continue;
        if (len + 1 >= cap)
        {
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb)
            {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        buf[len++] = (char)c;
    }
    if (c == EOF && !any)
    {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* ---- response helpers ----------------------------------------------------- */
static void send_response(const cJSON *id, cJSON *result /*consumed*/)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddItemToObject(resp, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    cJSON_AddItemToObject(resp, "result", result ? result : cJSON_CreateObject());
    write_message(resp);
    cJSON_Delete(resp);
}

static void send_error(const cJSON *id, int code, const char *message)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddItemToObject(resp, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    cJSON *err = cJSON_CreateObject();
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message);
    cJSON_AddItemToObject(resp, "error", err);
    write_message(resp);
    cJSON_Delete(resp);
}

/* ---- method handlers ------------------------------------------------------ */
static void handle_initialize(const cJSON *id, const cJSON *params)
{
    const char *proto = SIMCP_PROTOCOL_VERSION;
    if (params)
    {
        const cJSON *pv = cJSON_GetObjectItemCaseSensitive(params, "protocolVersion");
        if (pv && cJSON_IsString(pv) && pv->valuestring[0])
            proto = pv->valuestring;
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "protocolVersion", proto);

    cJSON *caps = cJSON_CreateObject();
    cJSON *toolsCap = cJSON_CreateObject();
    cJSON_AddBoolToObject(toolsCap, "listChanged", 0);
    cJSON_AddItemToObject(caps, "tools", toolsCap);
    cJSON *promptsCap = cJSON_CreateObject();
    cJSON_AddBoolToObject(promptsCap, "listChanged", 0);
    cJSON_AddItemToObject(caps, "prompts", promptsCap);
    cJSON_AddItemToObject(result, "capabilities", caps);

    cJSON *info = cJSON_CreateObject();
    cJSON_AddStringToObject(info, "name", SIMCP_SERVER_NAME);
    cJSON_AddStringToObject(info, "version", SIMCP_SERVER_VERSION);
    cJSON_AddItemToObject(result, "serverInfo", info);

    cJSON_AddStringToObject(result, "instructions", mcp_instructions());

    send_response(id, result);
}

static void handle_tools_list(const cJSON *id)
{
    size_t count = 0;
    const Tool **tools = mcp_tools(&count);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        const Tool *t = tools[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", t->name);
        if (t->title)
            cJSON_AddStringToObject(item, "title", t->title);
        cJSON_AddStringToObject(item, "description", t->description);

        cJSON *schema = t->inputSchema ? cJSON_Parse(t->inputSchema) : NULL;
        if (!schema)
        {
            schema = cJSON_CreateObject();
            cJSON_AddStringToObject(schema, "type", "object");
        }
        cJSON_AddItemToObject(item, "inputSchema", schema);

        cJSON *ann = cJSON_CreateObject();
        if (t->title)
            cJSON_AddStringToObject(ann, "title", t->title);
        cJSON_AddBoolToObject(ann, "readOnlyHint", t->destructive ? 0 : 1);
        cJSON_AddBoolToObject(ann, "destructiveHint", t->destructive ? 1 : 0);
        cJSON_AddItemToObject(item, "annotations", ann);

        cJSON_AddItemToArray(arr, item);
    }
    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "tools", arr);
    send_response(id, result);
}

/* Runs a tool handler under an SEH guard so a fault in low-level code becomes a
 * clean error result rather than crashing the whole server. */
static cJSON *run_tool_guarded(const Tool *t, const cJSON *args, int *isError)
{
    cJSON *res = NULL;
    __try
    {
        res = t->fn(args, isError);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *isError = 1;
        res = cJSON_CreateObject();
        char buf[128];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "The '%s' handler raised an exception (code 0x%08lX). The request was aborted safely.",
            t->name, (unsigned long)GetExceptionCode());
        cJSON_AddStringToObject(res, "error", buf);
    }
    return res;
}

static void handle_tools_call(const cJSON *id, const cJSON *params)
{
    const char *name = params ? mcp_arg_str(params, "name", NULL) : NULL;
    const cJSON *args = params ? cJSON_GetObjectItemCaseSensitive(params, "arguments") : NULL;
    if (args && !cJSON_IsObject(args))
        args = NULL;

    if (!name)
    {
        send_error(id, -32602, "Missing tool name in params.name");
        return;
    }

    const Tool *t = mcp_find_tool(name);
    if (!t)
    {
        cJSON *result = cJSON_CreateObject();
        cJSON *content = cJSON_CreateArray();
        cJSON *text = cJSON_CreateObject();
        cJSON_AddStringToObject(text, "type", "text");
        char msg[160];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "Unknown tool '%s'. Call tools/list to see available tools.", name);
        cJSON_AddStringToObject(text, "text", msg);
        cJSON_AddItemToArray(content, text);
        cJSON_AddItemToObject(result, "content", content);
        cJSON_AddBoolToObject(result, "isError", 1);
        send_response(id, result);
        return;
    }

    /* Guard destructive tools behind an explicit confirm=true. */
    if (t->destructive && !mcp_arg_bool(args, "confirm", 0))
    {
        cJSON *result = cJSON_CreateObject();
        cJSON *content = cJSON_CreateArray();
        cJSON *text = cJSON_CreateObject();
        cJSON_AddStringToObject(text, "type", "text");
        char msg[256];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "'%s' performs a destructive or irreversible action and is guarded. "
            "Re-issue the exact same call with \"confirm\": true to proceed.", name);
        cJSON_AddStringToObject(text, "text", msg);
        cJSON_AddItemToArray(content, text);
        cJSON_AddItemToObject(result, "content", content);
        cJSON_AddBoolToObject(result, "isError", 1);
        send_response(id, result);
        return;
    }

    int isError = 0;
    cJSON *toolResult = run_tool_guarded(t, args, &isError);
    if (!toolResult)
        toolResult = cJSON_CreateObject();

    /* Auto-detect error objects the handler returned via mcp_err(). */
    if (cJSON_IsObject(toolResult) && cJSON_GetObjectItemCaseSensitive(toolResult, "error"))
        isError = 1;

    /* Wrap into MCP tools/call result. */
    cJSON *result = cJSON_CreateObject();
    cJSON *content = cJSON_CreateArray();
    cJSON *text = cJSON_CreateObject();
    cJSON_AddStringToObject(text, "type", "text");
    char *pretty = cJSON_Print(toolResult);
    cJSON_AddStringToObject(text, "text", pretty ? pretty : "{}");
    if (pretty)
        cJSON_free(pretty);
    cJSON_AddItemToArray(content, text);
    cJSON_AddItemToObject(result, "content", content);
    cJSON_AddBoolToObject(result, "isError", isError ? 1 : 0);
    /* structuredContent must be an object; wrap arrays. */
    if (cJSON_IsObject(toolResult))
        cJSON_AddItemToObject(result, "structuredContent", toolResult);
    else
    {
        cJSON *wrap = cJSON_CreateObject();
        cJSON_AddItemToObject(wrap, "result", toolResult);
        cJSON_AddItemToObject(result, "structuredContent", wrap);
    }

    send_response(id, result);
}

static void handle_prompts_list(const cJSON *id)
{
    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "prompts", mcp_prompts_list());
    send_response(id, result);
}

static void handle_prompts_get(const cJSON *id, const cJSON *params)
{
    const char *name = params ? mcp_arg_str(params, "name", NULL) : NULL;
    const cJSON *args = params ? cJSON_GetObjectItemCaseSensitive(params, "arguments") : NULL;
    if (!name)
    {
        send_error(id, -32602, "Missing prompt name");
        return;
    }
    cJSON *result = mcp_prompt_get(name, args);
    if (!result)
    {
        send_error(id, -32602, "Unknown prompt");
        return;
    }
    send_response(id, result);
}

static void handle_message(cJSON *msg)
{
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(msg, "id");
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(msg, "method");
    const cJSON *params = cJSON_GetObjectItemCaseSensitive(msg, "params");
    int isNotification = (id == NULL);

    if (!method || !cJSON_IsString(method))
    {
        if (!isNotification)
            send_error(id, -32600, "Invalid Request: missing method");
        return;
    }
    const char *m = method->valuestring;

    if (strcmp(m, "initialize") == 0)
        handle_initialize(id, params);
    else if (strcmp(m, "tools/list") == 0)
        handle_tools_list(id);
    else if (strcmp(m, "tools/call") == 0)
        handle_tools_call(id, params);
    else if (strcmp(m, "prompts/list") == 0)
        handle_prompts_list(id);
    else if (strcmp(m, "prompts/get") == 0)
        handle_prompts_get(id, params);
    else if (strcmp(m, "ping") == 0)
        send_response(id, cJSON_CreateObject());
    else if (strcmp(m, "resources/list") == 0)
    {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddItemToObject(r, "resources", cJSON_CreateArray());
        send_response(id, r);
    }
    else if (strcmp(m, "resources/templates/list") == 0)
    {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddItemToObject(r, "resourceTemplates", cJSON_CreateArray());
        send_response(id, r);
    }
    else if (strncmp(m, "notifications/", 14) == 0)
    {
        /* fire-and-forget: no response */
    }
    else
    {
        if (!isNotification)
            send_error(id, -32601, "Method not found");
    }
}

int main(void)
{
    /* Binary stdio so JSON bytes pass through untouched. */
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    setvbuf(stderr, NULL, _IONBF, 0);

    mcp_register_all_tools();

    size_t toolCount = 0;
    (void)mcp_tools(&toolCount);
    fprintf(stderr, "[si-mcp] System Informer MCP server v%s ready (%zu tools)\n",
        SIMCP_SERVER_VERSION, toolCount);

    char *line;
    while ((line = read_line()) != NULL)
    {
        if (line[0] == '\0')
        {
            free(line);
            continue;
        }
        cJSON *msg = cJSON_Parse(line);
        free(line);
        if (!msg)
        {
            send_error(NULL, -32700, "Parse error");
            continue;
        }
        handle_message(msg);
        cJSON_Delete(msg);
    }
    return 0;
}
