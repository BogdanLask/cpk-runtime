# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.16)
project(cpk-runtime VERSION 1.0.0
        DESCRIPTION "Dependency-free C11 runtime reader for CRI CPK archives and CRILAYLA entries"
        LANGUAGES C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CPKRT_TOP_LEVEL ON)
else()
    set(CPKRT_TOP_LEVEL OFF)
endif()

option(CPKRT_BUILD_TESTS "Build the test suite" ON)
option(CPKRT_BUILD_BENCHMARKS "Build the synthetic benchmark executable" OFF)
option(CPKRT_BUILD_EXAMPLES "Build the example programs" ${CPKRT_TOP_LEVEL})
option(CPKRT_BUILD_FILE_ADAPTER "Build the POSIX/Win32 positional file adapter" ON)
option(CPKRT_BUILD_FUZZERS "Build the libFuzzer harness (Clang only)" OFF)
option(CPKRT_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
set(CPKRT_FUZZ_SECONDS 20 CACHE STRING "Seconds per harness for the fuzz_smoke target")

if(CPKRT_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "CPKRT_SANITIZE requires GCC or Clang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

function(cpkrt_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

add_library(cpkrt
    src/asset.c
    src/cpk.c
    src/cpk_assets.c
    src/crilayla.c
)
add_library(cpkrt::cpkrt ALIAS cpkrt)
set_target_properties(cpkrt PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
target_include_directories(cpkrt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
if(CPKRT_BUILD_FILE_ADAPTER)
    if(WIN32)
        target_sources(cpkrt PRIVATE src/platform/windows/file.c)
    elseif(UNIX)
        target_sources(cpkrt PRIVATE src/platform/posix/file.c)
    else()
        message(FATAL_ERROR
            "No file adapter for this platform; configure with -DCPKRT_BUILD_FILE_ADAPTER=OFF")
    endif()
endif()
cpkrt_warnings(cpkrt)

include(GNUInstallDirs)
install(TARGETS cpkrt EXPORT cpkrtTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/cpkrt DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT cpkrtTargets NAMESPACE cpkrt::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpkrt)

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/cpkrtConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cpkrtConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpkrt)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cpkrtConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cpkrtConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cpkrtConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cpkrt)

if(CPKRT_BUILD_TESTS)
    if(NOT CPKRT_BUILD_FILE_ADAPTER)
        message(FATAL_ERROR "The test suite requires CPKRT_BUILD_FILE_ADAPTER=ON")
    endif()
    enable_testing()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    add_executable(cpkrt_tests tests/test_asset.c)
    target_link_libraries(cpkrt_tests PRIVATE cpkrt)
    cpkrt_warnings(cpkrt_tests)
    foreach(case identity ownership failures arguments empty read_into read_into_too_small
                 read_into_unsupported read_into_arguments read_into_defensive)
        add_test(NAME asset_${case} COMMAND cpkrt_tests ${case})
    endforeach()

    add_executable(cpkrt_probe tests/cpk_probe.c)
    target_link_libraries(cpkrt_probe PRIVATE cpkrt)
    cpkrt_warnings(cpkrt_probe)
    add_test(NAME crilayla_arguments COMMAND cpkrt_probe arguments)

    foreach(case toc extended legacy encrypted bounds lifecycle literals references
                 decode_errors provider_raw provider_packed provider_contracts
                 files_errors fixture_cli)
        add_test(NAME cpk_${case}
                 COMMAND ${Python3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_cpk_contract.py
                         $<TARGET_FILE:cpkrt_probe> ${case})
        set_tests_properties(cpk_${case} PROPERTIES
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()

    add_test(NAME fuzz_corpus_fresh
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/make_fuzz_corpus.py
                     --check ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/seeds)
    set_tests_properties(fuzz_corpus_fresh PROPERTIES
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()

if(CPKRT_BUILD_EXAMPLES)
    if(CPKRT_BUILD_FILE_ADAPTER)
        add_executable(cpkrt_dump examples/dump_entry.c)
        target_link_libraries(cpkrt_dump PRIVATE cpkrt)
        cpkrt_warnings(cpkrt_dump)

        add_executable(cpkrt_index examples/index_only.c)
        target_link_libraries(cpkrt_index PRIVATE cpkrt)
        cpkrt_warnings(cpkrt_index)
    else()
        message(STATUS "CPKRT_BUILD_EXAMPLES is ignored: CPKRT_BUILD_FILE_ADAPTER is OFF")
    endif()
endif()

if(CPKRT_BUILD_BENCHMARKS)
    add_executable(cpkrt_bench bench/bench_cpk.c)
    target_link_libraries(cpkrt_bench PRIVATE cpkrt)
    cpkrt_warnings(cpkrt_bench)
    if(CPKRT_BUILD_FILE_ADAPTER)
        target_compile_definitions(cpkrt_bench PRIVATE CPKRT_BENCH_FILE_ADAPTER=1)
    endif()
endif()

if(CPKRT_BUILD_FUZZERS)
    if(CPKRT_BUILD_TESTS OR CPKRT_BUILD_BENCHMARKS OR CPKRT_BUILD_EXAMPLES)
        message(FATAL_ERROR
            "A fuzz build requires -DCPKRT_BUILD_TESTS=OFF "
            "-DCPKRT_BUILD_BENCHMARKS=OFF -DCPKRT_BUILD_EXAMPLES=OFF: the "
            "instrumented static library cannot be linked into normal "
            "executables without the sanitizer runtime")
    endif()
    if(NOT CPKRT_FUZZ_SECONDS MATCHES "^[0-9]+$")
        message(FATAL_ERROR "CPKRT_FUZZ_SECONDS must be a non-negative integer")
    endif()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "CPKRT_BUILD_FUZZERS requires Clang")
    endif()

    # Instrument the library itself so libFuzzer sees coverage in cpkrt, not
    # only in the harness. The harness supplies the fuzzer runtime.
    target_compile_options(cpkrt PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)

    add_executable(cpkrt_fuzz tests/fuzz_cpk.c)
    target_link_libraries(cpkrt_fuzz PRIVATE cpkrt)
    cpkrt_warnings(cpkrt_fuzz)
    target_compile_options(cpkrt_fuzz PRIVATE -fsanitize=fuzzer,address,undefined
                                             -fno-omit-frame-pointer)
    target_link_options(cpkrt_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)

    set(CPKRT_FUZZ_RUN_DIR ${CMAKE_BINARY_DIR}/fuzz-run)
    add_custom_target(fuzz_smoke
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/seeds
                ${CPKRT_FUZZ_RUN_DIR}/corpus
        COMMAND ${CMAKE_COMMAND} -E make_directory
                ${CPKRT_FUZZ_RUN_DIR}/artifacts_cpkrt_fuzz
        COMMAND $<TARGET_FILE:cpkrt_fuzz>
                -max_total_time=${CPKRT_FUZZ_SECONDS}
                -rss_limit_mb=3072
                -max_len=65536
                -dict=${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_cpk.dict
                -artifact_prefix=${CPKRT_FUZZ_RUN_DIR}/artifacts_cpkrt_fuzz/
                ${CPKRT_FUZZ_RUN_DIR}/corpus
        DEPENDS cpkrt_fuzz
        COMMENT "Fuzzing cpkrt_fuzz for ${CPKRT_FUZZ_SECONDS}s"
        VERBATIM)
endif()
