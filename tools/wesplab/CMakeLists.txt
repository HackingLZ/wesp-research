cmake_minimum_required(VERSION 3.24)
project(wesplab VERSION 0.2.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "wesplab-runtime targets Windows; use wesplab.py for offline analysis")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only x64 and ARM64 are supported")
endif()

set(EXPORT_DEF "${CMAKE_CURRENT_SOURCE_DIR}/data/espclient-0.1.0.156346177.def")
file(STRINGS "${EXPORT_DEF}" EXPORT_LINES REGEX "^[ \t]+Esp[A-Za-z0-9_]+")
set(EXPECTED_EXPORTS "")
foreach(LINE IN LISTS EXPORT_LINES)
    string(STRIP "${LINE}" NAME)
    string(APPEND EXPECTED_EXPORTS "    \"${NAME}\",\n")
endforeach()
list(LENGTH EXPORT_LINES EXPECTED_EXPORT_COUNT)
if(NOT EXPECTED_EXPORT_COUNT EQUAL 120)
    message(FATAL_ERROR "Expected 120 espclient exports, found ${EXPECTED_EXPORT_COUNT}")
endif()
configure_file(src/expected_exports.inc.in generated/expected_exports.inc @ONLY)

add_executable(wesplab-runtime src/main.cpp)
target_compile_features(wesplab-runtime PRIVATE cxx_std_20)
target_include_directories(wesplab-runtime PRIVATE include "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(wesplab-runtime PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(wesplab-runtime PRIVATE advapi32 bcrypt ole32 version)
if(MSVC)
    target_compile_options(wesplab-runtime PRIVATE /W4 /WX /permissive- /guard:cf /sdl)
    target_link_options(wesplab-runtime PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
else()
    target_compile_options(wesplab-runtime PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_options(wesplab-runtime PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()

install(TARGETS wesplab-runtime RUNTIME DESTINATION bin)
install(FILES
    data/protocol-0.1.0.156346177.tsv
    data/export-signatures-0.1.0.156346177.tsv
    data/event-families-0.1.0.156346177.json
    data/notification-layouts-0.1.0.156346177.json
    DESTINATION share/wesplab)
