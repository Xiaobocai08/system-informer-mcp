#include "mcp.h"
#include "tools.h"

void mcp_register_all_tools(void)
{
    register_system_tools();
    register_process_tools();
    register_thread_tools();
    register_memory_tools();
    register_handle_tools();
    register_service_tools();
    register_network_tools();
    register_module_tools();
    register_window_tools();
    register_file_tools();
    register_gui_tools();
}
