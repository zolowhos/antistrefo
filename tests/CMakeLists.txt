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
add_executable(re_test_disasm test_disasm.c test_disasm_vec.c test_disasm_arm64.c)
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

# Console band, ring scrollback, and hover-wheel hit targets for the GUI layout.
add_executable(re_test_console test_console.c)
target_link_libraries(re_test_console PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_console
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_console PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME console COMMAND re_test_console)

# Top-bar menu hover open and leave-dismiss (dropdown stays while over its items).
add_executable(re_test_gui_menu test_gui_menu.c
    ${CMAKE_SOURCE_DIR}/src/cli/screen/re_gui_menu.c)
target_link_libraries(re_test_gui_menu PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_gui_menu
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_gui_menu PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME gui_menu COMMAND re_test_gui_menu)

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

add_test(NAME agent_feedback
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_agent_feedback.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_agent_feedback.cmake)

# Imm search must report truncated:true when --limit caps a page with more hits.
add_executable(re_emit_imm_page emit_imm_page.c)
if(MSVC)
    set_property(TARGET re_emit_imm_page
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_emit_imm_page PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME imm_truncated
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_emit_imm_page>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_imm_page.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_imm_truncated.cmake)

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

# Universal decompile/agent contracts on synthetic PE only (no titled binaries).
add_executable(re_test_qa_contracts test_qa_contracts.c)
target_link_libraries(re_test_qa_contracts PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_qa_contracts
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_qa_contracts PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME qa_contracts COMMAND re_test_qa_contracts)

# Field-offset agent gaps: imm snap, decompile reg+disp, imm filter (synthetic PE).
add_executable(re_test_field_offset test_field_offset.c)
target_link_libraries(re_test_field_offset PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_field_offset
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_field_offset PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME field_offset COMMAND re_test_field_offset)

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

# ida-mcp tool result shapes (open/list/execute_query/reference/save/close).
add_test(NAME mcp_ida_shapes
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/mcp_ida_shapes.jsonl
        -DFIXTURE=${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_fixture.sys
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_mcp_ida_shapes.cmake)

# Discrete ida-pro-mcp Tier A content + Tier B unsupported stub.
add_test(NAME mcp_ida_discrete
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/mcp_ida_discrete.jsonl
        -DFIXTURE=${CMAKE_CURRENT_BINARY_DIR}/mcp_ida_discrete_fixture.sys
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_mcp_ida_discrete.cmake)

# GUI load console line and the live context snapshot MCP agents read.
add_executable(re_test_mcp_live test_mcp_live.c
    ${CMAKE_SOURCE_DIR}/src/mcp/re_mcp_live.c)
target_link_libraries(re_test_mcp_live PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_mcp_live
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_mcp_live PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME mcp_live COMMAND re_test_mcp_live)

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

add_executable(re_test_dc_text test_dc_text.c)
target_link_libraries(re_test_dc_text PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_dc_text
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_dc_text PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dc_text COMMAND re_test_dc_text)

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

# Ordered loads of an exact name list. The sequence, a shared export address, and
# a hole that is not one contiguous gap are each pinned on a synthetic image.
add_executable(re_test_nameref test_nameref.c)
target_link_libraries(re_test_nameref PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_nameref
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_nameref PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME nameref COMMAND re_test_nameref)

# User renames in a .alt sidecar: round-trip the file format and prove the name
# lands on the function table the GUI and decompiler read.
add_executable(re_test_alt test_alt.c)
target_link_libraries(re_test_alt PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_alt
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_alt PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME alt COMMAND re_test_alt)

add_executable(re_test_db test_db.c)
target_link_libraries(re_test_db PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_db
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_db PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME db COMMAND re_test_db)

# rename command writes .alt and funcs must echo the new display name.
add_test(NAME alt_rename
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_alt_rename_fixture.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_alt_rename.cmake)

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

# Large sparse PE: map+idle open must not retain a second full-file arena copy.
add_executable(re_test_large_mem test_large_mem.c)
target_link_libraries(re_test_large_mem PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_large_mem
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_large_mem PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME large_mem COMMAND re_test_large_mem)

# Checked-in packed / obfuscated PE fixtures: info and triage must not crash.
# Exit 0 with schema, or a clean documented nonzero with schema, both pass.
add_test(NAME robustness_fixtures
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DFIXTURES=${CMAKE_CURRENT_SOURCE_DIR}/fixtures
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_robustness_fixtures.cmake)
