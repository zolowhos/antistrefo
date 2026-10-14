# run_mcp_tools_list.cmake - verify MCP tools/list matches the ida-mcp names.
# Module: test (CMake).
# Owns: end-to-end validation of ida-compatible tool names and schemas.
# Depends: antistrefo executable and the MCP initialize/tools-list fixture.
if(NOT DEFINED ANTISTREFO OR NOT DEFINED INPUT)
    message(FATAL_ERROR "ANTISTREFO and INPUT are required")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" mcp
    INPUT_FILE "${INPUT}"
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error_output
    RESULT_VARIABLE status)
if(NOT status STREQUAL "0")
    message(FATAL_ERROR "MCP exited with status ${status}: ${error_output}")
endif()

string(REPLACE "\r\n" "\n" output "${output}")
string(REGEX MATCHALL "[^\n]+" frames "${output}")
list(LENGTH frames frame_count)
if(NOT frame_count EQUAL 2)
    message(FATAL_ERROR "expected initialize and tools/list responses, got ${frame_count}")
endif()
list(GET frames 1 tools_frame)

string(JSON tool_count ERROR_VARIABLE json_error LENGTH "${tools_frame}" result tools)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "tools/list response is not valid JSON: ${json_error}")
endif()

set(required_tools
    open_database
    execute_query
    reference
    list_databases
    save_database
    close_database
    context)
foreach(want IN LISTS required_tools)
    set(found 0)
    math(EXPR last_index "${tool_count} - 1")
    foreach(index RANGE 0 ${last_index})
        string(JSON tool_name ERROR_VARIABLE json_error GET
            "${tools_frame}" result tools ${index} name)
        if(tool_name STREQUAL "${want}")
            set(found 1)
            break()
        endif()
    endforeach()
    if(NOT found)
        message(FATAL_ERROR "tools/list missing ${want}")
    endif()
endforeach()

# Legacy CLI tools must not appear on the MCP surface.
foreach(legacy IN ITEMS info funcs disasm session_open session_list)
    math(EXPR last_index "${tool_count} - 1")
    foreach(index RANGE 0 ${last_index})
        string(JSON tool_name ERROR_VARIABLE json_error GET
            "${tools_frame}" result tools ${index} name)
        if(tool_name STREQUAL "${legacy}")
            message(FATAL_ERROR "tools/list must not include legacy tool ${legacy}")
        endif()
    endforeach()
endforeach()

# open_database path is required, matching ida-mcp.
set(open_index -1)
math(EXPR last_index "${tool_count} - 1")
foreach(index RANGE 0 ${last_index})
    string(JSON tool_name ERROR_VARIABLE json_error GET
        "${tools_frame}" result tools ${index} name)
    if(tool_name STREQUAL "open_database")
        set(open_index ${index})
        break()
    endif()
endforeach()
string(JSON path_type ERROR_VARIABLE json_error GET
    "${tools_frame}" result tools ${open_index} inputSchema properties path type)
if(NOT json_error STREQUAL "NOTFOUND" OR NOT path_type STREQUAL "string")
    message(FATAL_ERROR "open_database path property should be a string: ${json_error}")
endif()
string(JSON req0 ERROR_VARIABLE json_error GET
    "${tools_frame}" result tools ${open_index} inputSchema required 0)
if(NOT req0 STREQUAL "path")
    message(FATAL_ERROR "open_database required[0] should be path, got ${req0}")
endif()
