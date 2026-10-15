# run_agent_feedback.cmake - content pins for MCP agent feedback fixes.
# Module: test (CMake).
# Owns: disasm bounds/mid-insn, search imm insn_text, strings pattern, honesty.
# Depends: antistrefo, PE fixture emitter (re_test_cfg --emit).
if(NOT DEFINED ANTISTREFO OR NOT DEFINED EMITTER OR NOT DEFINED WORK)
    message(FATAL_ERROR "ANTISTREFO, EMITTER, and WORK are required")
endif()

execute_process(COMMAND "${EMITTER}" --emit "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

# Fixture text starts at IMAGE_BASE+0x1000 = 0x180001000. Mid-insn: +1 into cmp.
set(fn_va "0x180001000")
set(mid_va "0x180001001")

execute_process(
    COMMAND "${ANTISTREFO}" disasm "${WORK}" "${mid_va}"
    OUTPUT_VARIABLE dis_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "disasm failed: ${rc}: ${dis_out}")
endif()
if(NOT dis_out MATCHES "\"func_va\":\"0x180001000\"")
    message(FATAL_ERROR "disasm missing func_va: ${dis_out}")
endif()
if(NOT dis_out MATCHES "\"func_size\":")
    message(FATAL_ERROR "disasm missing func_size: ${dis_out}")
endif()
if(NOT dis_out MATCHES "\"func_end\":")
    message(FATAL_ERROR "disasm missing func_end: ${dis_out}")
endif()
if(NOT dis_out MATCHES "\"mid_insn\":true")
    message(FATAL_ERROR "disasm mid-insn snap missing: ${dis_out}")
endif()
if(NOT dis_out MATCHES "\"insn_va\":\"0x180001000\"")
    message(FATAL_ERROR "disasm insn_va should snap to function start: ${dis_out}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}" "${fn_va}"
    OUTPUT_VARIABLE funcs_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "funcs by address failed: ${rc}: ${funcs_out}")
endif()
if(NOT funcs_out MATCHES "\"total\":1")
    message(FATAL_ERROR "funcs by address should return one function: ${funcs_out}")
endif()
if(NOT funcs_out MATCHES "\"end\":")
    message(FATAL_ERROR "funcs should emit end: ${funcs_out}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" decompile "${WORK}" "${fn_va}"
    OUTPUT_VARIABLE dc_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "decompile failed: ${rc}: ${dc_out}")
endif()
if(NOT dc_out MATCHES "\"at\":\"0x180001000\"")
    message(FATAL_ERROR "decompile missing at: ${dc_out}")
endif()
if(NOT dc_out MATCHES "\"func_va\":\"0x180001000\"")
    message(FATAL_ERROR "decompile missing func_va: ${dc_out}")
endif()
if(NOT dc_out MATCHES "\"displacements\"")
    message(FATAL_ERROR "decompile missing displacements: ${dc_out}")
endif()

# imm:01 matches the cmp immediate and the mov eax,1 / mov eax,2 immediates in .text.
execute_process(
    COMMAND "${ANTISTREFO}" search "${WORK}" "imm:01" --limit 5
    OUTPUT_VARIABLE search_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "search imm failed: ${rc}: ${search_out}")
endif()
if(NOT search_out MATCHES "\"va\":")
    message(FATAL_ERROR "search hits need va: ${search_out}")
endif()
if(NOT search_out MATCHES "\"rva\":")
    message(FATAL_ERROR "search hits need rva: ${search_out}")
endif()
if(NOT search_out MATCHES "\"insn_text\"")
    message(FATAL_ERROR "search executable hits need insn_text: ${search_out}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" strings "${WORK}" --pattern Alpha
    OUTPUT_VARIABLE str_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "strings pattern failed: ${rc}: ${str_out}")
endif()
if(NOT str_out MATCHES "AlphaFunc")
    message(FATAL_ERROR "strings --pattern should be literal substring: ${str_out}")
endif()
if(NOT str_out MATCHES "\"pattern\":\"Alpha\"")
    message(FATAL_ERROR "strings should echo pattern: ${str_out}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" xrefs "${WORK}" "${fn_va}"
    OUTPUT_VARIABLE xref_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "xrefs failed: ${rc}: ${xref_out}")
endif()
# kind is always present on each ref; from_text when decode works.
if(NOT xref_out MATCHES "\"kind\":")
    message(FATAL_ERROR "xrefs should emit kind: ${xref_out}")
endif()

message(STATUS "agent feedback content pins ok")
file(REMOVE "${WORK}")
