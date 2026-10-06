# CMakeLists.txt - build for the antistrefo static analyzer and MCP server.
# Module: build (CMake).
# Owns: targets, the utility static lib, the exe, tests, and the format gate.
# Depends: CMake 3.25 or newer, a C11 and C++17 compiler. Rules in .rules/rules.md.
cmake_minimum_required(VERSION 3.25)

project(antistrefo
    VERSION 0.1.0
    DESCRIPTION "AI driven static analyzer for reverse engineering applications, libraries, or whatever you want"
    LANGUAGES C CXX)

# Third party CMake lists below 3.5 are rejected by CMake 4, so keep an escape
# hatch for vendored dependencies.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Oldest policy version allowed")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(RE_ENABLE_DISASM "Build the Capstone backed disassembler" ON)
option(RE_WERROR "Treat warnings as errors" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The include root is src/, so utilities are reached as utils/re_arena.h and
# features as features/pe/re_pe.h.
add_library(re_flags INTERFACE)
target_compile_features(re_flags INTERFACE c_std_11)
if(MSVC)
    target_compile_options(re_flags INTERFACE
        /W4
        /permissive- /Zc:__cplusplus
        $<$<BOOL:${RE_WERROR}>:/WX>
        # MSVC would otherwise guess the codepage of each source file.
        /utf-8)
else()
    target_compile_options(re_flags INTERFACE
        -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual
        $<$<BOOL:${RE_WERROR}>:-Werror>)
endif()

# ---- re_utils: the shared utility layer, C11, no exceptions and no globals ----
file(GLOB_RECURSE RE_UTIL_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/utils/*.c)
file(GLOB_RECURSE RE_UTIL_HEADERS CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/utils/*.h)

add_library(re_utils STATIC ${RE_UTIL_SOURCES} ${RE_UTIL_HEADERS})
target_include_directories(re_utils PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(re_utils PRIVATE re_flags)

if(MSVC)
    # Static CRT keeps antistrefo.exe dependency free, which is the whole point.
    set_property(TARGET re_utils PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_utils PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# ---- re_core: the feature layer, C11, parses untrusted bytes ----
# Recursive so a feature can own a directory, which is what src/features/disasm
# does to keep the architecture backends together and separately gated.
file(GLOB_RECURSE RE_FEATURE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/features/*.c)
file(GLOB_RECURSE RE_FEATURE_HEADERS CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/features/*.h)

add_library(re_core STATIC ${RE_FEATURE_SOURCES} ${RE_FEATURE_HEADERS})
target_include_directories(re_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(re_core PUBLIC re_utils PRIVATE re_flags)
if(RE_ENABLE_DISASM)
    target_compile_definitions(re_core PUBLIC RE_ENABLE_DISASM=1)
endif()

# ---- antistrefo: one binary, two modes ----
add_executable(antistrefo
src/cli/app/main.cpp
    src/cli/app/re_table.c
    src/cli/app/re_shell.c
    src/cli/cmds/re_cmds.c
    src/cli/cmds/re_cmds2.c
    src/cli/cmds/re_cmds3.c
    src/cli/cmds/re_cmds4.c
    src/cli/cmds/re_cmds5.c
    src/cli/cmds/re_prep.c
    src/cli/cmds/re_analyze_cmd.c
    src/cli/render/re_report.c
    src/cli/render/re_render.c
    src/cli/render/re_render2.c
    src/cli/render/re_render3.c
    src/cli/screen/re_input.c
    src/cli/screen/re_focus.c
    src/cli/screen/re_draw.c
    src/cli/screen/re_term.c
    src/cli/screen/re_gui_model.c
    src/cli/screen/re_gui.c
    src/mcp/re_mcp.cpp
    src/mcp/re_mcp_tools.cpp)
target_link_libraries(antistrefo PRIVATE re_core re_flags)
if(WIN32)
    target_link_libraries(antistrefo PRIVATE comdlg32)
endif()
if(MSVC)
    set_property(TARGET antistrefo PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(antistrefo PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# ---- tools the gate depends on ----
find_program(RE_CLANG_FORMAT
    NAMES clang-format
    HINTS "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/bin")
find_program(RE_PYTHON NAMES python3 python)

file(GLOB_RECURSE RE_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/src/*.cpp
    ${CMAKE_SOURCE_DIR}/src/*.h)

if(RE_CLANG_FORMAT)
    add_custom_target(re_format
        COMMAND ${RE_CLANG_FORMAT} -i --style=file ${RE_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Formatting all sources with clang-format")
    add_test(NAME format
        COMMAND ${RE_CLANG_FORMAT} -n --Werror --style=file ${RE_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
else()
    message(WARNING "clang-format not found, the format gate is disabled")
endif()

if(RE_PYTHON)
    add_custom_target(re_check
        COMMAND ${RE_PYTHON} ${CMAKE_SOURCE_DIR}/scripts/check.py ${CMAKE_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running the project rule gate")
    add_test(NAME style
        COMMAND ${RE_PYTHON} ${CMAKE_SOURCE_DIR}/scripts/check.py ${CMAKE_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
else()
    message(WARNING "python not found, the style gate is disabled")
endif()

# ---- tests ----
enable_testing()
add_subdirectory(tests)
