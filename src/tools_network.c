#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

static const char *tcp_state_name(DWORD s)
{
    switch (s)
    {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "?";
    }
}

static void ip4(char *out, size_t cap, DWORD addr, DWORD port)
{
    struct in_addr a; a.S_un.S_addr = addr;
    char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, ip, sizeof(ip));
    _snprintf_s(out, cap, _TRUNCATE, "%s:%u", ip, ntohs((USHORT)port));
}

static void ip6(char *out, size_t cap, const UCHAR *addr, DWORD port)
{
    struct in6_addr a; memcpy(&a, addr, 16);
    char ip[INET6_ADDRSTRLEN]; inet_ntop(AF_INET6, &a, ip, sizeof(ip));
    _snprintf_s(out, cap, _TRUNCATE, "[%s]:%u", ip, ntohs((USHORT)port));
}

/* cached pid -> image name lookups are cheap enough to do inline */
static void add_owner(cJSON *o, DWORD pid)
{
    cJSON_AddNumberToObject(o, "pid", pid);
    HANDLE h = ntu_open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, NULL);
    if (h) { char *p = ntu_process_image_path(h); if (p) { cJSON_AddStringToObject(o, "processImage", p); free(p); } NtClose(h); }
}

/* Collects all connections into an array; applies optional pid/state filters. */
static void collect_tcp4(cJSON *arr, DWORD pidFilter, int listenOnly)
{
    ULONG size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!size) return;
    PMIB_TCPTABLE_OWNER_PID t = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!t) return;
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < t->dwNumEntries; i++)
        {
            MIB_TCPROW_OWNER_PID *r = &t->table[i];
            if (pidFilter && r->dwOwningPid != pidFilter) continue;
            if (listenOnly && r->dwState != MIB_TCP_STATE_LISTEN) continue;
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "protocol", "TCP");
            char l[64], rem[64];
            ip4(l, sizeof(l), r->dwLocalAddr, r->dwLocalPort);
            ip4(rem, sizeof(rem), r->dwRemoteAddr, r->dwRemotePort);
            cJSON_AddStringToObject(o, "local", l);
            cJSON_AddStringToObject(o, "remote", rem);
            cJSON_AddStringToObject(o, "state", tcp_state_name(r->dwState));
            add_owner(o, r->dwOwningPid);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(t);
}

static void collect_tcp6(cJSON *arr, DWORD pidFilter, int listenOnly)
{
    ULONG size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!size) return;
    PMIB_TCP6TABLE_OWNER_PID t = (PMIB_TCP6TABLE_OWNER_PID)malloc(size);
    if (!t) return;
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < t->dwNumEntries; i++)
        {
            MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
            if (pidFilter && r->dwOwningPid != pidFilter) continue;
            if (listenOnly && r->dwState != MIB_TCP_STATE_LISTEN) continue;
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "protocol", "TCPv6");
            char l[80], rem[80];
            ip6(l, sizeof(l), r->ucLocalAddr, r->dwLocalPort);
            ip6(rem, sizeof(rem), r->ucRemoteAddr, r->dwRemotePort);
            cJSON_AddStringToObject(o, "local", l);
            cJSON_AddStringToObject(o, "remote", rem);
            cJSON_AddStringToObject(o, "state", tcp_state_name(r->dwState));
            add_owner(o, r->dwOwningPid);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(t);
}

static void collect_udp4(cJSON *arr, DWORD pidFilter)
{
    ULONG size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (!size) return;
    PMIB_UDPTABLE_OWNER_PID t = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!t) return;
    if (GetExtendedUdpTable(t, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < t->dwNumEntries; i++)
        {
            MIB_UDPROW_OWNER_PID *r = &t->table[i];
            if (pidFilter && r->dwOwningPid != pidFilter) continue;
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "protocol", "UDP");
            char l[64]; ip4(l, sizeof(l), r->dwLocalAddr, r->dwLocalPort);
            cJSON_AddStringToObject(o, "local", l);
            cJSON_AddStringToObject(o, "state", "");
            add_owner(o, r->dwOwningPid);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(t);
}

static void collect_udp6(cJSON *arr, DWORD pidFilter)
{
    ULONG size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (!size) return;
    PMIB_UDP6TABLE_OWNER_PID t = (PMIB_UDP6TABLE_OWNER_PID)malloc(size);
    if (!t) return;
    if (GetExtendedUdpTable(t, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < t->dwNumEntries; i++)
        {
            MIB_UDP6ROW_OWNER_PID *r = &t->table[i];
            if (pidFilter && r->dwOwningPid != pidFilter) continue;
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "protocol", "UDPv6");
            char l[80]; ip6(l, sizeof(l), r->ucLocalAddr, r->dwLocalPort);
            cJSON_AddStringToObject(o, "local", l);
            cJSON_AddStringToObject(o, "state", "");
            add_owner(o, r->dwOwningPid);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(t);
}

/* ---- network_connections -------------------------------------------------- */
static cJSON *tool_network_connections(const cJSON *args, int *isError)
{
    (void)isError;
    DWORD pidFilter = (DWORD)mcp_arg_u64(args, "pid", 0, NULL);
    const char *proto = mcp_arg_str(args, "protocol", "all");
    int listenOnly = mcp_arg_bool(args, "listening_only", 0);
    int wantTcp = _stricmp(proto, "all") == 0 || _stricmp(proto, "tcp") == 0;
    int wantUdp = _stricmp(proto, "all") == 0 || _stricmp(proto, "udp") == 0;

    cJSON *arr = cJSON_CreateArray();
    if (wantTcp) { collect_tcp4(arr, pidFilter, listenOnly); collect_tcp6(arr, pidFilter, listenOnly); }
    if (wantUdp && !listenOnly) { collect_udp4(arr, pidFilter); collect_udp6(arr, pidFilter); }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "count", cJSON_GetArraySize(arr));
    cJSON_AddItemToObject(result, "connections", arr);
    return result;
}

/* ---- port_owner ----------------------------------------------------------- */
static cJSON *tool_port_owner(const cJSON *args, int *isError)
{
    int found = 0;
    DWORD port = (DWORD)mcp_arg_u64(args, "port", 0, &found);
    if (!found) { *isError = 1; return mcp_err_hint("Pass the TCP/UDP port number as \"port\".", "Missing required argument: port"); }
    const char *proto = mcp_arg_str(args, "protocol", "all");
    int wantTcp = _stricmp(proto, "all") == 0 || _stricmp(proto, "tcp") == 0;
    int wantUdp = _stricmp(proto, "all") == 0 || _stricmp(proto, "udp") == 0;

    cJSON *all = cJSON_CreateArray();
    if (wantTcp) { collect_tcp4(all, 0, 0); collect_tcp6(all, 0, 0); }
    if (wantUdp) { collect_udp4(all, 0); collect_udp6(all, 0); }

    cJSON *matches = cJSON_CreateArray();
    cJSON *it;
    char suffix[16]; _snprintf_s(suffix, sizeof(suffix), _TRUNCATE, ":%lu", (unsigned long)port);
    cJSON_ArrayForEach(it, all)
    {
        const char *local = cJSON_GetStringValue(cJSON_GetObjectItem(it, "local"));
        if (!local) continue;
        size_t ll = strlen(local), sl = strlen(suffix);
        if (ll >= sl && strcmp(local + ll - sl, suffix) == 0)
            cJSON_AddItemToArray(matches, cJSON_Duplicate(it, 1));
    }
    cJSON_Delete(all);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "port", port);
    cJSON_AddNumberToObject(result, "matches", cJSON_GetArraySize(matches));
    cJSON_AddItemToObject(result, "owners", matches);
    return result;
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_network_tools[] = {
    { "network_connections", "Network connections",
      "The System Informer 'Network' tab: all TCP/UDP (IPv4+IPv6) endpoints with local/remote address:port, TCP "
      "state, and the owning process (pid + image path). Filter by pid to see one process's connections, by "
      "protocol, or listening_only for servers. Use to answer 'what is this process talking to?' or 'what is "
      "listening?'.",
      "{\"type\":\"object\",\"properties\":{"
      "\"pid\":{\"type\":[\"integer\",\"string\"],\"description\":\"Only connections owned by this process.\"},"
      "\"protocol\":{\"type\":\"string\",\"enum\":[\"all\",\"tcp\",\"udp\"],\"default\":\"all\"},"
      "\"listening_only\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Only TCP listeners.\"}"
      "},\"additionalProperties\":false}", 0, tool_network_connections },

    { "port_owner", "Find port owner",
      "Identify which process is using a given TCP/UDP port (local port match across IPv4/IPv6). The direct answer "
      "to 'what's using port 3000?'. Returns each matching endpoint with its owning pid and image path.",
      "{\"type\":\"object\",\"properties\":{"
      "\"port\":{\"type\":[\"integer\",\"string\"],\"description\":\"Port number to look up.\"},"
      "\"protocol\":{\"type\":\"string\",\"enum\":[\"all\",\"tcp\",\"udp\"],\"default\":\"all\"}"
      "},\"required\":[\"port\"],\"additionalProperties\":false}", 0, tool_port_owner },
};

void register_network_tools(void)
{
    for (size_t i = 0; i < sizeof(g_network_tools) / sizeof(g_network_tools[0]); i++)
        mcp_register_tool(&g_network_tools[i]);
}
