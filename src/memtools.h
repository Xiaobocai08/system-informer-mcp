/* Internal sharing between tools_memory.c and tools_memory2.c */
#ifndef SIMCP_MEMTOOLS_H
#define SIMCP_MEMTOOLS_H
#include "ntutil.h"
#include "mcp.h"

cJSON *tool_process_memory_regions(const cJSON *args, int *isError);
cJSON *tool_process_memory_summary(const cJSON *args, int *isError);
cJSON *tool_read_process_memory(const cJSON *args, int *isError);
cJSON *tool_write_process_memory(const cJSON *args, int *isError);
cJSON *tool_protect_process_memory(const cJSON *args, int *isError);

#endif
