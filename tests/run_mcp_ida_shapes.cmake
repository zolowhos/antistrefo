# run_mcp_ida_shapes.cmake - pin ida-mcp tool result shapes via MCP tools/call.
# Module: test (CMake).
# Owns: open/list/execute_python/reference/save/close structuredContent checks.
# Depends: antistrefo, PE fixture emitter, mcp_ida_shapes.jsonl.
if(NOT DEFINED ANTISTREFO OR NOT DEFINED INPUT OR NOT DEFINED FIXTURE OR NOT DEFINED EMITTER)
    message(FATAL_ERROR "ANTISTREFO, INPUT, FIXTURE, and EMITTER are required")
endif()

execute_process(COMMAND "${EMITTER}" --emit "${FIXTURE}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy "${INPUT}" "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_shapes.run.jsonl"
    RESULT_VARIABLE copy_status)
if(NOT copy_status STREQUAL "0")
    message(FATAL_ERROR "copy fixture script failed")
endif()

file(READ "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_shapes.run.jsonl" script)
string(REPLACE "__FIXTURE__" "${FIXTURE}" script "${script}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_shapes.run.jsonl" "${script}")

execute_process(
    COMMAND "${ANTISTREFO}" mcp
    INPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_shapes.run.jsonl"
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error_output
    RESULT_VARIABLE status)
if(NOT status STREQUAL "0")
    message(FATAL_ERROR "MCP exited with status ${status}: ${error_output}")
endif()

string(REPLACE "\r\n" "\n" output "${output}")
string(REGEX MATCHALL "[^\n]+" frames "${output}")
list(LENGTH frames frame_count)
# initialize + 6 tool results (notification has no response)
if(frame_count LESS 7)
    message(FATAL_ERROR "expected at least 7 MCP frames, got ${frame_count}")
endif()

list(GET frames 1 open_frame)
string(JSON instance_id ERROR_VARIABLE json_error GET
    "${open_frame}" result structuredContent instance_id)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "open_database missing instance_id: ${json_error}")
endif()
if(instance_id STREQUAL "")
    message(FATAL_ERROR "open_database instance_id empty")
endif()
string(JSON backend ERROR_VARIABLE json_error GET
    "${open_frame}" result structuredContent backend)
if(NOT backend STREQUAL "idalib")
    message(FATAL_ERROR "open_database backend should be idalib, got ${backend}")
endif()
string(JSON status_field ERROR_VARIABLE json_error GET
    "${open_frame}" result structuredContent status)
if(NOT status_field STREQUAL "current")
    message(FATAL_ERROR "open_database status should be current, got ${status_field}")
endif()
string(JSON recovery ERROR_VARIABLE json_error GET
    "${open_frame}" result structuredContent recovery)
if(NOT recovery STREQUAL "none")
    message(FATAL_ERROR "open_database recovery should be none")
endif()

list(GET frames 2 list_frame)
string(JSON inst0_path ERROR_VARIABLE json_error GET
    "${list_frame}" result structuredContent instances 0 path)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "list_databases instances[0].path missing: ${json_error}")
endif()
string(JSON inst0_id ERROR_VARIABLE json_error GET
    "${list_frame}" result structuredContent instances 0 instance_id)
if(NOT inst0_id STREQUAL "${instance_id}")
    message(FATAL_ERROR "list_databases instance_id mismatch")
endif()

list(GET frames 3 py_frame)
string(JSON py_result ERROR_VARIABLE json_error GET
    "${py_frame}" result structuredContent result)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "execute_python missing result: ${json_error}")
endif()
if(NOT py_result EQUAL 2)
    message(FATAL_ERROR "execute_python 1+1 should be 2, got ${py_result}")
endif()
string(JSON py_stdout ERROR_VARIABLE json_error GET
    "${py_frame}" result structuredContent stdout)
string(JSON py_stderr ERROR_VARIABLE json_error GET
    "${py_frame}" result structuredContent stderr)
if(NOT json_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "execute_python missing stdout/stderr")
endif()

list(GET frames 4 ref_frame)
string(JSON ref_text ERROR_VARIABLE json_error GET
    "${ref_frame}" result structuredContent)
# reference returns a JSON string in structuredContent
if(NOT ref_text MATCHES "Decompile")
    message(FATAL_ERROR "reference should mention Decompile, got ${ref_text}")
endif()

list(GET frames 5 save_frame)
string(JSON save_err ERROR_VARIABLE json_error GET
    "${save_frame}" result isError)
if(NOT save_err)
    message(FATAL_ERROR "save_database should set isError")
endif()

list(GET frames 6 close_frame)
string(JSON closed ERROR_VARIABLE json_error GET
    "${close_frame}" result structuredContent closed)
if(NOT closed)
    message(FATAL_ERROR "close_database should return closed=true")
endif()
