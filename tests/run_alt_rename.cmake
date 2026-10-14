# run_alt_rename.cmake - rename persists in .alt and appears in funcs output.
# Module: test (CMake).
# Owns: end-to-end rename -> sidecar -> funcs name pin.
# Depends: antistrefo and the fixture emitter from re_test_cfg.
execute_process(COMMAND "${EMITTER}" --emit "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" rename "${WORK}" "0x1000" "renamed_entry"
    OUTPUT_VARIABLE ren RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "rename failed with ${rc}: ${ren}")
endif()
if(NOT ren MATCHES "renamed_entry")
    message(FATAL_ERROR "rename response missing the new name: ${ren}")
endif()
if(NOT EXISTS "${WORK}.alt")
    message(FATAL_ERROR "expected sidecar ${WORK}.alt after rename")
endif()
file(READ "${WORK}.alt" alt_text)
if(NOT alt_text MATCHES "0x1000=renamed_entry")
    message(FATAL_ERROR "sidecar format wrong: ${alt_text}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}"
    OUTPUT_VARIABLE out RESULT_VARIABLE rc2)
if(NOT rc2 EQUAL 0)
    message(FATAL_ERROR "funcs failed with ${rc2}: ${out}")
endif()
if(NOT out MATCHES "renamed_entry")
    message(FATAL_ERROR "renamed name did not reach funcs output: ${out}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" list_names "${WORK}"
    OUTPUT_VARIABLE listed RESULT_VARIABLE rc3)
if(NOT rc3 EQUAL 0)
    message(FATAL_ERROR "list_names failed with ${rc3}: ${listed}")
endif()
if(NOT listed MATCHES "renamed_entry")
    message(FATAL_ERROR "list_names missing rename: ${listed}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" decompile "${WORK}" "0x1000"
    OUTPUT_VARIABLE dec RESULT_VARIABLE rc4)
if(NOT rc4 EQUAL 0)
    message(FATAL_ERROR "decompile failed with ${rc4}: ${dec}")
endif()
if(NOT dec MATCHES "renamed_entry")
    message(FATAL_ERROR "renamed name did not reach decompile: ${dec}")
endif()

file(REMOVE "${WORK}")
file(REMOVE "${WORK}.alt")
message(STATUS "rename persists in .alt and appears in funcs/decompile/list_names")
