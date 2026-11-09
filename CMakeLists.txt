cmake_minimum_required(VERSION 3.16)
project(Oculus C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Oculus v1 requires 64-bit Windows")
endif()

add_library(oculus_core STATIC
  src/errors.c src/process.c src/modules.c src/pe_exports.c
  src/injection.c src/x64_decode.c src/hook.c src/repl.c)
target_include_directories(oculus_core PUBLIC include PRIVATE src)
target_compile_definitions(oculus_core PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
if(MINGW)
  target_compile_options(oculus_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(oculus src/main.c)
target_link_libraries(oculus PRIVATE oculus_core)

add_executable(oculus_sample_target samples/target/main.c)
target_compile_definitions(oculus_sample_target PRIVATE UNICODE _UNICODE)

add_library(oculus_sample_replacement SHARED samples/replacement_dll/replacement.c)
set_target_properties(oculus_sample_replacement PROPERTIES PREFIX "" OUTPUT_NAME "oculus_sample_replacement")

enable_testing()
add_executable(test_parser tests/test_parser.c)
target_link_libraries(test_parser PRIVATE oculus_core)
target_include_directories(test_parser PRIVATE src)
add_test(NAME parser COMMAND test_parser)

add_executable(test_integration tests/test_integration.c)
target_link_libraries(test_integration PRIVATE oculus_core)
add_test(NAME integration COMMAND test_integration
  $<TARGET_FILE:oculus_sample_target> $<TARGET_FILE:oculus_sample_replacement>)
set_tests_properties(integration PROPERTIES TIMEOUT 20)
