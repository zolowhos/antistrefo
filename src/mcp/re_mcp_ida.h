// re_mcp_ida.h - discrete ida-pro-mcp style MCP command entry points.
// Module: mcp (C++17).
// Owns: Tier A read/write wrappers and Tier B unsupported stubs.
// Depends: re_table. Implemented in re_mcp_ida_read.cpp / re_mcp_ida_write.cpp.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

/* Tier A - connection and metadata */
int re_cmd_check_connection(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_metadata(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_convert_number(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_current_address(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_current_function(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_entry_points(re_ctx_t *ctx, const char *path, int argc, char **argv);

/* Tier A - function lookup and call graph */
int re_cmd_get_function_by_name(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_function_by_address(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_callees(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_callers(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_stack_frame_variables(re_ctx_t *ctx, const char *path, int argc, char **argv);

/* Tier A - memory and globals */
int re_cmd_read_memory_bytes(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_data_read_byte(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_data_read_word(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_data_read_dword(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_data_read_qword(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_data_read_string(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_global_variable_value_by_name(re_ctx_t *ctx, const char *path, int argc,
                                             char **argv);
int re_cmd_get_global_variable_value_at_address(re_ctx_t *ctx, const char *path, int argc,
                                                char **argv);

/* Tier A - rename alias */
int re_cmd_rename_function(re_ctx_t *ctx, const char *path, int argc, char **argv);

/* Tier B - unsupported stubs */
int re_cmd_list_local_types(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_set_comment(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_rename_local_variable(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_rename_global_variable(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_set_global_variable_type(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_patch_address_assembles(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_set_function_prototype(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_declare_c_type(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_set_local_variable_type(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_defined_structures(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_analyze_struct_detailed(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_struct_at_address(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_struct_info_simple(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_search_structures(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_rename_stack_frame_variable(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_create_stack_frame_variable(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_set_stack_frame_variable_type(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_delete_stack_frame_variable(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_get_xrefs_to_field(re_ctx_t *ctx, const char *path, int argc, char **argv);

#ifdef __cplusplus
}
#endif
