# run_mcp_tools_list.cmake - verify the MCP tool list schemas parse as JSON.
# Module: test (CMake).
# Owns: end-to-end validation of path-based tool input schemas.
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
if(tool_count LESS 1)
    message(FATAL_ERROR "tools/list returned no tools")
endif()

set(info_index -1)
math(EXPR last_index "${tool_count} - 1")
foreach(index RANGE 0 ${last_index})
    string(JSON tool_name ERROR_VARIABLE json_error GET "${tools_frame}" result tools ${index} name)
    if(NOT json_error STREQUAL "NOTFOUND")
        message(FATAL_ERROR "could not read tool ${index}: ${json_error}")
    endif()
    if(tool_name STREQUAL "info")
        set(info_index ${index})
        break()
    endif()
endforeach()
if(info_index LESS 0)
    message(FATAL_ERROR "tools/list did not include the info tool")
endif()

set(context_index -1)
foreach(index RANGE 0 ${last_index})
    string(JSON tool_name ERROR_VARIABLE json_error GET "${tools_frame}" result tools ${index} name)
    if(tool_name STREQUAL "context")
        set(context_index ${index})
        break()
    endif()
endforeach()
if(context_index LESS 0)
    message(FATAL_ERROR "tools/list did not include the context tool")
endif()

string(JSON session_type ERROR_VARIABLE json_error GET
    "${tools_frame}" result tools ${info_index} inputSchema properties session type)
if(NOT json_error STREQUAL "NOTFOUND" OR NOT session_type STREQUAL "string")
    message(FATAL_ERROR "info session property should be a string: ${json_error}")
endif()
string(JSON offset_type ERROR_VARIABLE json_error GET
    "${tools_frame}" result tools ${info_index} inputSchema properties offset type)
if(NOT json_error STREQUAL "NOTFOUND" OR NOT offset_type STREQUAL "integer")
    message(FATAL_ERROR "info offset property should be an integer: ${json_error}")
endif()
string(JSON limit_type ERROR_VARIABLE json_error GET
    "${tools_frame}" result tools ${info_index} inputSchema properties limit type)
if(NOT json_error STREQUAL "NOTFOUND" OR NOT limit_type STREQUAL "integer")
    message(FATAL_ERROR "info limit property should be an integer: ${json_error}")
endif()
