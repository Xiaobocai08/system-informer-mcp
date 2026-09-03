#include "mcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* ---- registry ------------------------------------------------------------- */
#define SIMCP_MAX_TOOLS 256
static const Tool *g_tools[SIMCP_MAX_TOOLS];
static size_t g_tool_count;

void mcp_register_tool(const Tool *t)
{
    if (t && g_tool_count < SIMCP_MAX_TOOLS)
        g_tools[g_tool_count++] = t;
}

const Tool **mcp_tools(size_t *count)
{
    if (count)
        *count = g_tool_count;
    return g_tools;
}

const Tool *mcp_find_tool(const char *name)
{
    if (!name)
        return NULL;
    for (size_t i = 0; i < g_tool_count; i++)
    {
        if (strcmp(g_tools[i]->name, name) == 0)
            return g_tools[i];
    }
    return NULL;
}

/* ---- error / status objects ---------------------------------------------- */
static cJSON *verr(const char *hint, const char *fmt, va_list ap)
{
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "error", buf);
    if (hint)
        cJSON_AddStringToObject(o, "hint", hint);
    return o;
}

cJSON *mcp_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    cJSON *o = verr(NULL, fmt, ap);
    va_end(ap);
    return o;
}

cJSON *mcp_err_hint(const char *hint, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    cJSON *o = verr(hint, fmt, ap);
    va_end(ap);
    return o;
}

cJSON *mcp_ok(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "ok");
    cJSON_AddStringToObject(o, "message", buf);
    return o;
}

/* ---- argument helpers ----------------------------------------------------- */
int mcp_arg_present(const cJSON *args, const char *key)
{
    return args && cJSON_GetObjectItemCaseSensitive(args, key) != NULL;
}

unsigned long long mcp_arg_u64(const cJSON *args, const char *key, unsigned long long def, int *found)
{
    if (found)
        *found = 0;
    if (!args)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(args, key);
    if (!item)
        return def;
    if (cJSON_IsNumber(item))
    {
        if (found)
            *found = 1;
        if (item->valuedouble < 0)
            return def;
        return (unsigned long long)item->valuedouble;
    }
    if (cJSON_IsString(item) && item->valuestring && item->valuestring[0])
    {
        char *end = NULL;
        unsigned long long v = _strtoui64(item->valuestring, &end, 0); /* base 0: 0x.. hex, else dec */
        if (end && end != item->valuestring)
        {
            if (found)
                *found = 1;
            return v;
        }
    }
    return def;
}

long long mcp_arg_i64(const cJSON *args, const char *key, long long def)
{
    if (!args)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(args, key);
    if (!item)
        return def;
    if (cJSON_IsNumber(item))
        return (long long)item->valuedouble;
    if (cJSON_IsString(item) && item->valuestring && item->valuestring[0])
    {
        char *end = NULL;
        long long v = _strtoi64(item->valuestring, &end, 0);
        if (end && end != item->valuestring)
            return v;
    }
    return def;
}

int mcp_arg_bool(const cJSON *args, const char *key, int def)
{
    if (!args)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(args, key);
    if (!item)
        return def;
    if (cJSON_IsBool(item))
        return cJSON_IsTrue(item) ? 1 : 0;
    if (cJSON_IsNumber(item))
        return item->valuedouble != 0.0;
    if (cJSON_IsString(item) && item->valuestring)
        return (_stricmp(item->valuestring, "true") == 0 || strcmp(item->valuestring, "1") == 0);
    return def;
}

const char *mcp_arg_str(const cJSON *args, const char *key, const char *def)
{
    if (!args)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(args, key);
    if (item && cJSON_IsString(item) && item->valuestring)
        return item->valuestring;
    return def;
}
