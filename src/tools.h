/* Registrars for each tool group. Implemented in the tools_*.c files. */
#ifndef SIMCP_TOOLS_H
#define SIMCP_TOOLS_H

void register_system_tools(void);
void register_process_tools(void);
void register_thread_tools(void);
void register_memory_tools(void);
void register_handle_tools(void);
void register_service_tools(void);
void register_network_tools(void);
void register_module_tools(void);
void register_window_tools(void);
void register_file_tools(void);
void register_gui_tools(void);

#endif /* SIMCP_TOOLS_H */
