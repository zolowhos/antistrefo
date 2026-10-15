# run_mcp_ida_discrete.cmake - pin discrete ida-pro-mcp Tier A/B tool shapes.
# Module: test (CMake).
# Owns: check_connection, metadata, list_functions, convert, entry, Tier B stub.
# Depends: antistrefo, PE fixture emitter, mcp_ida_discrete.jsonl.
if(NOT DEFINED ANTISTREFO OR NOT DEFINED INPUT OR NOT DEFINED FIXTURE OR NOT DEFINED EMITTER)
    message(FATAL_ERROR "ANTISTREFO, INPUT, FIXTURE, and EMITTER are required")
endif()

execute_process(COMMAND "${EMITTER}" --emit "${FIXTURE}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy "${INPUT}" "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_discrete.run.jsonl"
    RESULT_VARIABLE copy_status)
if(NOT copy_status STREQUAL "0")
    message(FATAL_ERROR "copy fixture script failed")
endif()

file(READ "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_discrete.run.jsonl" script)
string(REPLACE "__FIXTURE__" "${FIXTURE}" script "${script}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_discrete.run.jsonl" "${script}")

execute_process(
    COMMAND "${ANTISTREFO}" mcp
    INPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_discrete.run.jsonl"
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error_output
    RESULT_VARIABLE status)
if(NOT status STREQUAL "0")
    message(FATAL_ERROR "MCP exited with status ${status}: ${error_output}")
endif()

string(REPLACE "\r\n" "\n" output "${output}")
string(REGEX MATCHALL "[^\n]+" frames "${output}")
list(LENGTH frames frame_count)
# initialize + open + check + metadata + list_functions + convert + entry + stub + close
if(frame_count LESS 9)
    message(FATAL_ERROR "expected at least 9 MCP frames, got ${frame_count}")
endif()

list(GET frames 2 conn_frame)
string(JSON ok ERROR_VARIABLE json_error GET
    "${conn_frame}" result structuredContent ok)
if(NOT ok)
    message(FATAL_ERROR "check_connection should return ok=true: ${json_error}")
endif()

list(GET frames 3 meta_frame)
string(JSON meta_tool ERROR_VARIABLE json_error GET
    "${meta_frame}" result structuredContent tool)
if(NOT meta_tool STREQUAL "info")
    message(FATAL_ERROR "get_metadata should wrap info, got ${meta_tool}")
endif()

list(GET frames 4 funcs_frame)
string(JSON funcs_tool ERROR_VARIABLE json_error GET
    "${funcs_frame}" result structuredContent tool)
if(NOT funcs_tool STREQUAL "funcs")
    message(FATAL_ERROR "list_functions should emit funcs tool field, got ${funcs_tool}")
endif()
string(JSON func_total ERROR_VARIABLE json_error GET
    "${funcs_frame}" result structuredContent total)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "list_functions missing total: ${json_error}")
endif()
if(func_total STREQUAL "0" OR func_total STREQUAL "")
    message(FATAL_ERROR "list_functions total should be > 0, got '${func_total}'")
endif()

list(GET frames 5 conv_frame)
string(JSON dec ERROR_VARIABLE json_error GET
    "${conv_frame}" result structuredContent decimal)
if(NOT dec STREQUAL "16")
    message(FATAL_ERROR "convert_number(0x10) decimal should be 16, got ${dec}")
endif()
string(JSON hex ERROR_VARIABLE json_error GET
    "${conv_frame}" result structuredContent hexadecimal)
if(NOT hex STREQUAL "0x10")
    message(FATAL_ERROR "convert_number hexadecimal should be 0x10, got ${hex}")
endif()

list(GET frames 6 entry_frame)
string(JSON entry_count ERROR_VARIABLE json_error GET
    "${entry_frame}" result structuredContent count)
if(NOT entry_count STREQUAL "1")
    message(FATAL_ERROR "get_entry_points count should be 1, got ${entry_count}")
endif()

list(GET frames 7 stub_frame)
string(JSON stub_err ERROR_VARIABLE json_error GET
    "${stub_frame}" result isError)
if(NOT stub_err)
    message(FATAL_ERROR "list_local_types should set isError")
endif()
string(JSON stub_code ERROR_VARIABLE json_error GET
    "${stub_frame}" result structuredContent error code)
if(NOT stub_code STREQUAL "unsupported")
    message(FATAL_ERROR "Tier B stub should be unsupported, got ${stub_code}")
endif()
