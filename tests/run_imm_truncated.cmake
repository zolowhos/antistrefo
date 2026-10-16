# run_imm_truncated.cmake - pin imm: search truncated when limit caps the page.
# Module: test (CMake).
# Owns: content checks that a full imm page reports truncated:true.
# Depends: antistrefo and emit_imm_page (five known imm32 hits).
if(NOT DEFINED ANTISTREFO OR NOT DEFINED EMITTER OR NOT DEFINED WORK)
    message(FATAL_ERROR "ANTISTREFO, EMITTER, and WORK are required")
endif()

execute_process(COMMAND "${EMITTER}" "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the imm page fixture: ${wrote}")
endif()

# Five planted mov eax,0xA1B2C3D4 hits; limit 2 must fill the page and say so.
execute_process(
    COMMAND "${ANTISTREFO}" search "${WORK}" "imm:a1b2c3d4" --limit 2
    OUTPUT_VARIABLE page_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "imm page search failed: ${rc}: ${page_out}")
endif()
if(NOT page_out MATCHES "\"total\":2")
    message(FATAL_ERROR "imm page with limit 2 should report total 2: ${page_out}")
endif()
if(NOT page_out MATCHES "\"truncated\":true")
    message(FATAL_ERROR "imm page with more hits must set truncated true: ${page_out}")
endif()

# Uncapped (relative to the fixture) reports every planted hit and not truncated.
execute_process(
    COMMAND "${ANTISTREFO}" search "${WORK}" "imm:a1b2c3d4" --limit 40
    OUTPUT_VARIABLE full_out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "imm full search failed: ${rc}: ${full_out}")
endif()
if(NOT full_out MATCHES "\"total\":5")
    message(FATAL_ERROR "imm fixture must have exactly five hits: ${full_out}")
endif()
if(NOT full_out MATCHES "\"truncated\":false")
    message(FATAL_ERROR "imm full page should not claim truncation: ${full_out}")
endif()
