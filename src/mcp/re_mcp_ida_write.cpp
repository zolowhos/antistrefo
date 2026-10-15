// re_mcp_ida_write.cpp - rename_function and Tier B unsupported MCP stubs.
// Module: mcp (C++17).
// Owns: write-side discrete tools and clear unsupported error envelopes.
// Depends: re_mcp_ida.h, re_cmds, re_jw. No fake success for deferred tools.
#include "mcp/re_mcp_ida.h"

#include "utils/json/re_json.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_str.h"
#include "cli/cmds/re_cmds.h"

#include <cstring>

namespace {

int unsupported(re_ctx_t *ctx, const char *name) {
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_jw_obj(&w);
    re_jw_key(&w, "error");
    re_jw_obj(&w);
    re_jw_kcstr(&w, "code", "unsupported");
    re_jw_kcstr(&w, "message", name);
    re_jw_obj_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    if (ctx->err)
        RE_ERR_SET(ctx->err, RE_E_UNSUPPORTED, name);
    return 5;
}

} // namespace

extern "C" int re_cmd_rename_function(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return re_cmd_rename(ctx, path, argc, argv);
}

#define RE_IDA_STUB(fn, msg)                                                    \
    extern "C" int fn(re_ctx_t *ctx, const char *path, int argc, char **argv) { \
        (void)path;                                                             \
        (void)argc;                                                             \
        (void)argv;                                                             \
        return unsupported(ctx, msg);                                           \
    }

RE_IDA_STUB(re_cmd_list_local_types, "list_local_types unsupported: no type library")
RE_IDA_STUB(re_cmd_set_comment, "set_comment unsupported: no comment store")
RE_IDA_STUB(re_cmd_rename_local_variable, "rename_local_variable unsupported")
RE_IDA_STUB(re_cmd_rename_global_variable,
            "rename_global_variable unsupported: use rename_function")
RE_IDA_STUB(re_cmd_set_global_variable_type, "set_global_variable_type unsupported")
RE_IDA_STUB(re_cmd_patch_address_assembles, "patch_address_assembles unsupported: read-only")
RE_IDA_STUB(re_cmd_set_function_prototype, "set_function_prototype unsupported")
RE_IDA_STUB(re_cmd_declare_c_type, "declare_c_type unsupported: no type DB")
RE_IDA_STUB(re_cmd_set_local_variable_type, "set_local_variable_type unsupported")
RE_IDA_STUB(re_cmd_get_defined_structures, "get_defined_structures unsupported")
RE_IDA_STUB(re_cmd_analyze_struct_detailed, "analyze_struct_detailed unsupported")
RE_IDA_STUB(re_cmd_get_struct_at_address, "get_struct_at_address unsupported")
RE_IDA_STUB(re_cmd_get_struct_info_simple, "get_struct_info_simple unsupported")
RE_IDA_STUB(re_cmd_search_structures, "search_structures unsupported")
RE_IDA_STUB(re_cmd_rename_stack_frame_variable, "rename_stack_frame_variable unsupported")
RE_IDA_STUB(re_cmd_create_stack_frame_variable, "create_stack_frame_variable unsupported")
RE_IDA_STUB(re_cmd_set_stack_frame_variable_type, "set_stack_frame_variable_type unsupported")
RE_IDA_STUB(re_cmd_delete_stack_frame_variable, "delete_stack_frame_variable unsupported")
RE_IDA_STUB(re_cmd_get_xrefs_to_field, "get_xrefs_to_field unsupported: no struct fields")
