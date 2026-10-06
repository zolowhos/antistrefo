# tests/CMakeLists.txt - CTest targets, one per suite, each printing only on failure.
# Module: test (CMake).
# Owns: the utility correctness suite and its runtime library setting.
# Depends: re_utils. The style and format gates are registered in the root file.
add_executable(re_test_utils test_utils.c test_features.c)
target_link_libraries(re_test_utils PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_utils
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_utils PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME utils COMMAND re_test_utils)

# The decoder suite is a separate binary so a length regression names itself in
# the CTest output instead of hiding inside the utility suite.
add_executable(re_test_disasm test_disasm.c test_disasm_vec.c)
target_link_libraries(re_test_disasm PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_disasm
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_disasm PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME disasm COMMAND re_test_disasm)

# The layout suite is separate for the same reason: a box that is one column short
# should name itself in the CTest output rather than hiding in the utility counts.
add_executable(re_test_tui test_tui.c)
target_link_libraries(re_test_tui PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_tui
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_tui PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME tui COMMAND re_test_tui)

# The screen grid and the reference arrangement. Named separately because a layout
# that has silently stopped composing looks exactly like a layout that never ran.
add_executable(re_test_screen test_screen.c)
target_link_libraries(re_test_screen PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_screen
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_screen PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME screen COMMAND re_test_screen)

# The interactive front end's pure half: the event decoder, the focus order, and the
# frame diff. The platform file is deliberately absent, because a test that needs a
# terminal is a test that only runs on somebody's machine.
add_executable(re_test_input test_input.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_input.c
    ${CMAKE_SOURCE_DIR}/src/cli/screen/re_focus.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_draw.c)
target_link_libraries(re_test_input PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_input
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_input PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME input COMMAND re_test_input)

# The command layer lives in the executable, so testing it means running it. This is
# the only automated coverage a command gets, and without it a command that silently
# answers "nothing references this" passes every other suite.
add_test(NAME xrefs_data
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_xrefs_fixture.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_xrefs_data.cmake)

# The control flow suite is separate because a graph that collapses to one block is
# the kind of regression that every other suite happily passes, so it gets its own
# binary and a hand assembled fixture whose every edge is known in advance.
add_executable(re_test_cfg test_cfg.c)
target_link_libraries(re_test_cfg PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_cfg
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_cfg PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME cfg COMMAND re_test_cfg)

# The stack suite is separate because the argument inference is the one pass whose
# failure is invisible: a wrong argument count still compiles to plausible output.
add_executable(re_test_stack test_stack.c)
target_link_libraries(re_test_stack PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_stack
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_stack PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME stack COMMAND re_test_stack)

# The JSON reader suite is separate because a reader that is lenient about a malformed
# frame is a protocol bug that shows up as a mysterious client disconnect.
add_executable(re_test_jr test_jr.c)
target_link_libraries(re_test_jr PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_jr
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_jr PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME jr COMMAND re_test_jr)

# The MCP command table is the source for tools/list, and every advertised input
# schema must be valid JSON for path-based tools as well as commands without a path.
add_test(NAME mcp_tools_list
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/mcp_tools_list.jsonl
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_mcp_tools_list.cmake)

# The lowering suite is separate because a wrong IR shape still prints plausible
# C, and only assertions on the ops themselves can tell a signed widening from
# an unsigned one or a carried add from a dropped carry.
add_executable(re_test_lower test_lower.c)
target_link_libraries(re_test_lower PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_lower
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_lower PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME lower COMMAND re_test_lower)

# The scoreboard suite is separate because a quality figure that silently stopped
# measuring reads exactly like a good one, and only assertions on the axes with
# known fixture answers can tell the difference.
add_executable(re_test_score test_score.c)
target_link_libraries(re_test_score PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_score
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_score PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME score COMMAND re_test_score)

# The decompiler corpus score. A missing fixture skips, so the suite is green
# before the ten files are mounted, and a present one prints hits over records.
add_executable(re_test_dc_score test_dc_score.c)
target_link_libraries(re_test_dc_score PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_score
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_score PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_score COMMAND re_test_dc_score)

# The expression folder. A prologue that is only saves and copies must print as
# two calls and a return, and a folded displacement must stay a load.
add_executable(re_test_dc_fold test_dc_fold.c)
target_link_libraries(re_test_dc_fold PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_fold
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_fold PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_fold COMMAND re_test_dc_fold)

# The Microsoft x64 force. A kernel import must not be reported as SysV, and a
# saved rbx must not become a parameter.
add_executable(re_test_dc_abi test_dc_abi.c)
target_link_libraries(re_test_dc_abi PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_abi
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_abi PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_abi COMMAND re_test_dc_abi)

# Import prototypes. A known name prints with its argument count; an unknown
# call is left alone.
add_executable(re_test_dc_proto test_dc_proto.c)
target_link_libraries(re_test_dc_proto PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_proto
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_proto PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_proto COMMAND re_test_dc_proto)

# Indirect calls. One reaching lea prints the function; a slot with no table
# stays slot_0x.
add_executable(re_test_dc_indirect test_dc_indirect.c)
target_link_libraries(re_test_dc_indirect PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_indirect
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_indirect PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_indirect COMMAND re_test_dc_indirect)

# The flow suite is separate because a transform that silently changed control
# flow, or folded a value the machine never held, still prints plausible C.
# Only assertions on hand built IR with known answers can tell a recovery pass
# from a corruption pass.
add_executable(re_test_flow test_flow.c)
target_link_libraries(re_test_flow PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_flow
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_flow PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME flow COMMAND re_test_flow)

# The naming suite is separate because a class name that quietly stopped landing
# on functions reads exactly like an image with no RTTI, and only assertions on a
# fixture whose slots and functions are known in advance can tell the difference.
add_executable(re_test_names test_names.c)
target_link_libraries(re_test_names PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_names
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_names PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME names COMMAND re_test_names)

# The signature suite is separate because a matcher that has stopped matching, or an
# index that has stopped finding, reads exactly like a database that holds nothing.
add_executable(re_test_flirt test_flirt.c)
target_link_libraries(re_test_flirt PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_flirt
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_flirt PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME flirt COMMAND re_test_flirt)

# The naming chain end to end: a signature file in, a name in the report out. Both
# halves have unit coverage, and only a run proves the halves are connected.
add_test(NAME flirt_names
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_flirt_fixture.sys
        -DSIGS=${CMAKE_CURRENT_BINARY_DIR}/re_flirt_probe.sig
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_flirt_names.cmake)

# The recovery cases reach the report or they do not: bytes the walk could not
# decode, an overlapping body, a body past the instruction ceiling and a tail that
# cannot return. Each is a field in the funcs output, and only a run proves it.
add_test(NAME walk_quality
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_walk_fixture.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_walk_quality.cmake)

# The PE suite is separate because "is this address code or data" is the question a
# wrong answer to makes every later pass quietly wrong, and the fixture it shares with
# the cfg suite lives in a header so the two cannot disagree about the bytes.
add_executable(re_test_pe test_pe.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_gui_model.c)
target_link_libraries(re_test_pe PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_pe
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_pe PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME pe COMMAND re_test_pe)
