#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <shlwapi.h>

static const char *svc_state(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "start_pending";
    case SERVICE_STOP_PENDING: return "stop_pending";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING: return "pause_pending";
    case SERVICE_PAUSED: return "paused";
    default: return "?";
    }
}
static const char *svc_start(DWORD s)
{
    switch (s) {
    case SERVICE_BOOT_START: return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START: return "auto";
    case SERVICE_DEMAND_START: return "demand";
    case SERVICE_DISABLED: return "disabled";
    default: return "?";
    }
}
static const char *svc_type(DWORD t, char *buf, size_t cap)
{
    buf[0] = 0;
    if (t & SERVICE_KERNEL_DRIVER) strcat_s(buf, cap, "kernel_driver,");
    if (t & SERVICE_FILE_SYSTEM_DRIVER) strcat_s(buf, cap, "fs_driver,");
    if (t & SERVICE_WIN32_OWN_PROCESS) strcat_s(buf, cap, "win32_own,");
    if (t & SERVICE_WIN32_SHARE_PROCESS) strcat_s(buf, cap, "win32_shared,");
    if (t & SERVICE_USER_OWN_PROCESS) strcat_s(buf, cap, "user_own,");
    if (t & SERVICE_INTERACTIVE_PROCESS) strcat_s(buf, cap, "interactive,");
    size_t l = strlen(buf); if (l) buf[l-1] = 0;
    return buf;
}
static int start_from_name(const char *s, DWORD *out)
{
    if (!s) return 0;
    if (!_stricmp(s,"boot")){*out=SERVICE_BOOT_START;return 1;}
    if (!_stricmp(s,"system")){*out=SERVICE_SYSTEM_START;return 1;}
    if (!_stricmp(s,"auto")){*out=SERVICE_AUTO_START;return 1;}
    if (!_stricmp(s,"demand")||!_stricmp(s,"manual")){*out=SERVICE_DEMAND_START;return 1;}
    if (!_stricmp(s,"disabled")){*out=SERVICE_DISABLED;return 1;}
    return 0;
}

/* ---- list_services -------------------------------------------------------- */
static cJSON *tool_list_services(const cJSON *args, int *isError)
{
    const char *stateFilter = mcp_arg_str(args, "state", "all");
    const char *typeFilter = mcp_arg_str(args, "type", "all");
    const char *nameFilter = mcp_arg_str(args, "name_filter", NULL);
    unsigned long long limit = mcp_arg_u64(args, "limit", 0, NULL);

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { *isError = 1; return ntu_win_error("OpenSCManager", GetLastError()); }

    DWORD typeMask = SERVICE_WIN32 | SERVICE_DRIVER;
    if (!_stricmp(typeFilter, "driver")) typeMask = SERVICE_DRIVER;
    else if (!_stricmp(typeFilter, "win32")) typeMask = SERVICE_WIN32;
    DWORD stateMask = SERVICE_STATE_ALL;
    if (!_stricmp(stateFilter, "active")) stateMask = SERVICE_ACTIVE;
    else if (!_stricmp(stateFilter, "inactive")) stateMask = SERVICE_INACTIVE;

    DWORD bytes = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, typeMask, stateMask, NULL, 0, &bytes, &count, &resume, NULL);
    BYTE *buf = (BYTE *)malloc(bytes ? bytes : 1);
    cJSON *arr = cJSON_CreateArray();
    unsigned long total = 0, emitted = 0;
    if (buf && EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, typeMask, stateMask, buf, bytes, &bytes, &count, &resume, NULL))
    {
        ENUM_SERVICE_STATUS_PROCESSW *svc = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
        for (DWORD i = 0; i < count; i++)
        {
            char *name = ntu_w2u(svc[i].lpServiceName, -1);
            if (nameFilter && nameFilter[0] && name)
            {
                char *disp = ntu_w2u(svc[i].lpDisplayName, -1);
                int match = (StrStrIA(name, nameFilter) != NULL) || (disp && StrStrIA(disp, nameFilter) != NULL);
                free(disp);
                if (!match) { free(name); continue; }
            }
            total++;
            if (limit && emitted >= limit) { free(name); continue; }
            cJSON *o = cJSON_CreateObject();
            if (name) cJSON_AddStringToObject(o, "name", name);
            ntu_add_w(o, "displayName", svc[i].lpDisplayName);
            cJSON_AddStringToObject(o, "state", svc_state(svc[i].ServiceStatusProcess.dwCurrentState));
            char tb[96]; cJSON_AddStringToObject(o, "type", svc_type(svc[i].ServiceStatusProcess.dwServiceType, tb, sizeof(tb)));
            if (svc[i].ServiceStatusProcess.dwProcessId)
                cJSON_AddNumberToObject(o, "pid", svc[i].ServiceStatusProcess.dwProcessId);
            cJSON_AddItemToArray(arr, o);
            emitted++;
            free(name);
        }
    }
    free(buf);
    CloseServiceHandle(scm);
    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "total", (double)total);
    cJSON_AddNumberToObject(result, "returned", (double)emitted);
    cJSON_AddItemToObject(result, "services", arr);
    return result;
}

/* ---- service_details ------------------------------------------------------ */
static cJSON *tool_service_details(const cJSON *args, int *isError)
{
    const char *name = mcp_arg_str(args, "name", NULL);
    if (!name || !name[0]) { *isError = 1; return mcp_err_hint("Pass the service short name as \"name\" (from list_services).", "Missing required argument: name"); }
    PWSTR wname = ntu_u2w(name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { free(wname); *isError = 1; return ntu_win_error("OpenSCManager", GetLastError()); }
    SC_HANDLE svc = OpenServiceW(scm, wname, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    free(wname);
    if (!svc) { DWORD e=GetLastError(); CloseServiceHandle(scm); *isError = 1; return ntu_win_error("OpenService", e); }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "name", name);

    DWORD need = 0;
    QueryServiceConfigW(svc, NULL, 0, &need);
    LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)malloc(need ? need : 1);
    if (cfg && QueryServiceConfigW(svc, cfg, need, &need))
    {
        ntu_add_w(o, "displayName", cfg->lpDisplayName);
        char tb[96]; cJSON_AddStringToObject(o, "type", svc_type(cfg->dwServiceType, tb, sizeof(tb)));
        cJSON_AddStringToObject(o, "startType", svc_start(cfg->dwStartType));
        ntu_add_w(o, "binaryPath", cfg->lpBinaryPathName);
        ntu_add_w(o, "loadOrderGroup", cfg->lpLoadOrderGroup);
        ntu_add_w(o, "serviceStartName", cfg->lpServiceStartName);
    }
    free(cfg);

    /* description */
    QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &need);
    BYTE *db = (BYTE *)malloc(need ? need : 1);
    if (db && QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, db, need, &need))
    {
        SERVICE_DESCRIPTIONW *d = (SERVICE_DESCRIPTIONW *)db;
        if (d->lpDescription) ntu_add_w(o, "description", d->lpDescription);
    }
    free(db);

    SERVICE_STATUS_PROCESS ssp; DWORD b = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &b))
    {
        cJSON_AddStringToObject(o, "state", svc_state(ssp.dwCurrentState));
        if (ssp.dwProcessId) cJSON_AddNumberToObject(o, "pid", ssp.dwProcessId);
        cJSON_AddNumberToObject(o, "win32ExitCode", ssp.dwWin32ExitCode);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return o;
}

/* ---- control_service ------------------------------------------------------ */
static cJSON *tool_control_service(const cJSON *args, int *isError)
{
    const char *name = mcp_arg_str(args, "name", NULL);
    const char *action = mcp_arg_str(args, "action", NULL);
    if (!name || !action) { *isError = 1; return mcp_err_hint("Pass service \"name\" and \"action\" (start/stop/pause/continue/restart).", "Missing name or action"); }
    PWSTR wname = ntu_u2w(name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { free(wname); *isError = 1; return ntu_win_error("OpenSCManager", GetLastError()); }
    DWORD access = SERVICE_QUERY_STATUS;
    if (!_stricmp(action,"start")) access |= SERVICE_START;
    else if (!_stricmp(action,"stop")||!_stricmp(action,"restart")) access |= SERVICE_STOP | SERVICE_START;
    else access |= SERVICE_PAUSE_CONTINUE;
    SC_HANDLE svc = OpenServiceW(scm, wname, access);
    free(wname);
    if (!svc) { DWORD e=GetLastError(); CloseServiceHandle(scm); *isError = 1; return ntu_win_error("OpenService", e); }

    SERVICE_STATUS ss; BOOL ok = FALSE; DWORD err = 0;
    if (!_stricmp(action,"start")) { ok = StartServiceW(svc, 0, NULL); err = GetLastError(); }
    else if (!_stricmp(action,"stop")) { ok = ControlService(svc, SERVICE_CONTROL_STOP, &ss); err = GetLastError(); }
    else if (!_stricmp(action,"pause")) { ok = ControlService(svc, SERVICE_CONTROL_PAUSE, &ss); err = GetLastError(); }
    else if (!_stricmp(action,"continue")) { ok = ControlService(svc, SERVICE_CONTROL_CONTINUE, &ss); err = GetLastError(); }
    else if (!_stricmp(action,"restart"))
    {
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 50; i++) { SERVICE_STATUS_PROCESS s; DWORD b; if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,(LPBYTE)&s,sizeof(s),&b) && s.dwCurrentState==SERVICE_STOPPED) break; Sleep(100); }
        ok = StartServiceW(svc, 0, NULL); err = GetLastError();
    }
    else { CloseServiceHandle(svc); CloseServiceHandle(scm); *isError = 1; return mcp_err_hint("Valid actions: start, stop, pause, continue, restart.", "Unknown action '%s'", action); }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!ok) { *isError = 1; return ntu_win_error("ControlService", err); }
    return mcp_ok("Service '%s' %s requested", name, action);
}

/* ---- set_service_start_type ----------------------------------------------- */
static cJSON *tool_set_service_start_type(const cJSON *args, int *isError)
{
    const char *name = mcp_arg_str(args, "name", NULL);
    DWORD start;
    if (!name) { *isError = 1; return mcp_err("Missing required argument: name"); }
    if (!start_from_name(mcp_arg_str(args, "start_type", NULL), &start)) { *isError = 1; return mcp_err_hint("Valid: boot, system, auto, demand, disabled.", "Missing or invalid start_type"); }
    PWSTR wname = ntu_u2w(name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { free(wname); *isError = 1; return ntu_win_error("OpenSCManager", GetLastError()); }
    SC_HANDLE svc = OpenServiceW(scm, wname, SERVICE_CHANGE_CONFIG);
    free(wname);
    if (!svc) { DWORD e=GetLastError(); CloseServiceHandle(scm); *isError = 1; return ntu_win_error("OpenService", e); }
    BOOL ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    DWORD err = GetLastError();
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    if (!ok) { *isError = 1; return ntu_win_error("ChangeServiceConfig", err); }
    return mcp_ok("Service '%s' start type set to %s", name, mcp_arg_str(args, "start_type", ""));
}

/* ---- create_service / delete_service -------------------------------------- */
static cJSON *tool_create_service(const cJSON *args, int *isError)
{
    const char *name = mcp_arg_str(args, "name", NULL);
    const char *bin = mcp_arg_str(args, "binary_path", NULL);
    const char *disp = mcp_arg_str(args, "display_name", name);
    const char *stStr = mcp_arg_str(args, "start_type", "demand");
    const char *tyStr = mcp_arg_str(args, "service_type", "win32_own");
    if (!name || !bin) { *isError = 1; return mcp_err_hint("Pass \"name\" and \"binary_path\" (full path to the .exe/.sys).", "Missing name or binary_path"); }
    DWORD start; if (!start_from_name(stStr, &start)) start = SERVICE_DEMAND_START;
    DWORD type = SERVICE_WIN32_OWN_PROCESS;
    if (!_stricmp(tyStr,"kernel_driver")) type = SERVICE_KERNEL_DRIVER;
    else if (!_stricmp(tyStr,"fs_driver")) type = SERVICE_FILE_SYSTEM_DRIVER;
    else if (!_stricmp(tyStr,"win32_shared")) type = SERVICE_WIN32_SHARE_PROCESS;

    PWSTR wname = ntu_u2w(name), wbin = ntu_u2w(bin), wdisp = ntu_u2w(disp ? disp : name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { free(wname); free(wbin); free(wdisp); *isError = 1; return ntu_win_error("OpenSCManager(CREATE_SERVICE)", GetLastError()); }
    SC_HANDLE svc = CreateServiceW(scm, wname, wdisp, SERVICE_ALL_ACCESS, type, start, SERVICE_ERROR_NORMAL, wbin, NULL, NULL, NULL, NULL, NULL);
    DWORD err = GetLastError();
    free(wname); free(wbin); free(wdisp);
    if (!svc) { CloseServiceHandle(scm); *isError = 1; return ntu_win_error("CreateService", err); }
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return mcp_ok("Created service '%s'", name);
}

static cJSON *tool_delete_service(const cJSON *args, int *isError)
{
    const char *name = mcp_arg_str(args, "name", NULL);
    if (!name) { *isError = 1; return mcp_err("Missing required argument: name"); }
    PWSTR wname = ntu_u2w(name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { free(wname); *isError = 1; return ntu_win_error("OpenSCManager", GetLastError()); }
    SC_HANDLE svc = OpenServiceW(scm, wname, DELETE);
    free(wname);
    if (!svc) { DWORD e=GetLastError(); CloseServiceHandle(scm); *isError = 1; return ntu_win_error("OpenService(DELETE)", e); }
    BOOL ok = DeleteService(svc);
    DWORD err = GetLastError();
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    if (!ok) { *isError = 1; return ntu_win_error("DeleteService", err); }
    return mcp_ok("Service '%s' marked for deletion (removed once all handles close)", name);
}

/* ---- registration --------------------------------------------------------- */
#define SVC_NAME "\"name\":{\"type\":\"string\",\"description\":\"Service short name (key name), e.g. \\\"Spooler\\\". From list_services.\"}"
#define CONFIRM_PROP "\"confirm\":{\"type\":\"boolean\",\"description\":\"Must be true. This tool changes system state; refused without explicit confirmation.\"}"

static const Tool g_service_tools[] = {
    { "list_services", "List services",
      "The System Informer 'Services' tab: Windows services and drivers with short name, display name, current "
      "state (running/stopped/...), type, and pid when running. Filter by state (active/inactive), type "
      "(win32/driver) or a name/display substring. Use to inventory services or find a stopped one.",
      "{\"type\":\"object\",\"properties\":{"
      "\"state\":{\"type\":\"string\",\"enum\":[\"all\",\"active\",\"inactive\"],\"default\":\"all\"},"
      "\"type\":{\"type\":\"string\",\"enum\":[\"all\",\"win32\",\"driver\"],\"default\":\"all\"},"
      "\"name_filter\":{\"type\":\"string\",\"description\":\"Substring of name or display name.\"},"
      "\"limit\":{\"type\":\"integer\",\"default\":0}"
      "},\"additionalProperties\":false}", 0, tool_list_services },

    { "service_details", "Service details",
      "Full configuration for one service (System Informer service properties): display name, description, type, "
      "start type, binary path, load-order group, log-on account, current state, pid and exit code.",
      "{\"type\":\"object\",\"properties\":{" SVC_NAME "},\"required\":[\"name\"],\"additionalProperties\":false}", 0, tool_service_details },

    { "control_service", "Control service",
      "GUARDED (confirm=true required). Start, stop, pause, continue or restart a service (System Informer service "
      "context menu). Stopping a critical service can destabilise the system.",
      "{\"type\":\"object\",\"properties\":{" SVC_NAME ","
      "\"action\":{\"type\":\"string\",\"enum\":[\"start\",\"stop\",\"pause\",\"continue\",\"restart\"]},"
      CONFIRM_PROP "},\"required\":[\"name\",\"action\",\"confirm\"],\"additionalProperties\":false}", 1, tool_control_service },
    { "set_service_start_type", "Set service start type",
      "GUARDED (confirm=true required). Change a service's start type: boot, system, auto, demand (manual) or "
      "disabled (System Informer service properties).",
      "{\"type\":\"object\",\"properties\":{" SVC_NAME ","
      "\"start_type\":{\"type\":\"string\",\"enum\":[\"boot\",\"system\",\"auto\",\"demand\",\"disabled\"]},"
      CONFIRM_PROP "},\"required\":[\"name\",\"start_type\",\"confirm\"],\"additionalProperties\":false}", 1, tool_set_service_start_type },

    { "create_service", "Create service",
      "GUARDED (confirm=true required). Register a new Windows service or driver in the SCM. Provide a unique name "
      "and the full binary path. Does not start it (use control_service).",
      "{\"type\":\"object\",\"properties\":{" SVC_NAME ","
      "\"binary_path\":{\"type\":\"string\",\"description\":\"Full path to the service .exe (or .sys for drivers).\"},"
      "\"display_name\":{\"type\":\"string\",\"description\":\"Friendly name (defaults to name).\"},"
      "\"service_type\":{\"type\":\"string\",\"enum\":[\"win32_own\",\"win32_shared\",\"kernel_driver\",\"fs_driver\"],\"default\":\"win32_own\"},"
      "\"start_type\":{\"type\":\"string\",\"enum\":[\"boot\",\"system\",\"auto\",\"demand\",\"disabled\"],\"default\":\"demand\"},"
      CONFIRM_PROP "},\"required\":[\"name\",\"binary_path\",\"confirm\"],\"additionalProperties\":false}", 1, tool_create_service },

    { "delete_service", "Delete service",
      "GUARDED (confirm=true required). Remove a service from the SCM. Irreversible from this server. The service "
      "is deleted once all open handles to it close; stop it first if running.",
      "{\"type\":\"object\",\"properties\":{" SVC_NAME "," CONFIRM_PROP "},\"required\":[\"name\",\"confirm\"],\"additionalProperties\":false}", 1, tool_delete_service },
};

void register_service_tools(void)
{
    for (size_t i = 0; i < sizeof(g_service_tools) / sizeof(g_service_tools[0]); i++)
        mcp_register_tool(&g_service_tools[i]);
}
