# run_robustness_fixtures.cmake - smoke info/triage on packed and obfuscated PE.
# Module: test (CMake).
# Owns: open each checked-in robustness fixture and assert a schema response.
# Depends: antistrefo executable and tests/fixtures/*.bin. Pins no-crash only.
if(NOT ANTISTREFO)
    message(FATAL_ERROR "ANTISTREFO is required")
endif()
if(NOT FIXTURES)
    message(FATAL_ERROR "FIXTURES directory is required")
endif()

# Accept exit 0 with schema on stdout, or a documented nonzero with schema on
# stderr/stdout. A missing schema or a signal-style failure fails the test.
function(smoke_one cmd fixture)
    # Flags belong after the command name: `info <file> --format json`.
    execute_process(
        COMMAND "${ANTISTREFO}" "${cmd}" "${fixture}" --format json
        OUTPUT_VARIABLE out
        ERROR_VARIABLE err
        RESULT_VARIABLE rc
        TIMEOUT 30)
    set(blob "${out}\n${err}")
    if(NOT blob MATCHES "\"schema\"[ \t]*:[ \t]*\"antistrefo/1\"")
        message(FATAL_ERROR
            "${cmd} on ${fixture}: no antistrefo/1 schema (rc=${rc})\n"
            "stdout:\n${out}\nstderr:\n${err}")
    endif()
    # Documented CLI exits are 0..6. Anything else (e.g. 139 segfault) is a crash.
    if(rc LESS 0 OR rc GREATER 6)
        message(FATAL_ERROR
            "${cmd} on ${fixture}: crash-like exit ${rc}\n"
            "stdout:\n${out}\nstderr:\n${err}")
    endif()
    # PE fixtures must succeed with a tool payload. Non-PE may exit nonzero with
    # a schema-bearing error envelope (e.g. unsupported format).
    if(REQUIRE_OK)
        if(NOT rc EQUAL 0)
            message(FATAL_ERROR
                "${cmd} on ${fixture}: expected exit 0, got ${rc}\n"
                "stdout:\n${out}\nstderr:\n${err}")
        endif()
        if(NOT out MATCHES "\"tool\"")
            message(FATAL_ERROR
                "${cmd} on ${fixture}: exit 0 but no tool payload\n"
                "stdout:\n${out}\nstderr:\n${err}")
        endif()
    endif()
    message(STATUS "${cmd} ${fixture} -> rc=${rc} (schema ok)")
endfunction()

set(_pes
    "${FIXTURES}/packed_pe.bin"
    "${FIXTURES}/obfuscated_pe.bin")
foreach(_f IN LISTS _pes)
    if(NOT EXISTS "${_f}")
        message(FATAL_ERROR "missing fixture: ${_f}")
    endif()
    set(REQUIRE_OK TRUE)
    smoke_one(info "${_f}")
    smoke_one(triage "${_f}")
endforeach()

# ELF is format-corpus only; this build may refuse it cleanly (exit 5).
set(_elf "${FIXTURES}/minimal_elf.bin")
if(EXISTS "${_elf}")
    set(REQUIRE_OK FALSE)
    smoke_one(info "${_elf}")
endif()

message(STATUS "robustness fixtures smoke passed")
