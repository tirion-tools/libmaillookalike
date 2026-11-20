# libmaillookalike: lookalike and link-deception checks for mail clients (C++20).
#
#   maillookalike::maillookalike   psl.h (libpsl), url.h, links.h, lookalike.h    ICU (uc, i18n), libpsl
#
# Consumers add_subdirectory() this directory. A consumer's PkgConfig::ICU / PkgConfig::PSL targets are used when
# they exist; otherwise ICU and libpsl come from pkg-config. Built on its own (tools/gate.sh) it also builds the
# GoogleTest suites with strict warnings as errors, and with -DMAILLOOKALIKE_FUZZ=ON (clang) the libFuzzer targets.
cmake_minimum_required(VERSION 3.25)
project(maillookalike VERSION 0.1.2 LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
if(NOT TARGET PkgConfig::ICU)
  pkg_check_modules(ICU REQUIRED IMPORTED_TARGET GLOBAL icu-uc icu-i18n)
endif()
if(NOT TARGET PkgConfig::PSL)
  pkg_check_modules(PSL REQUIRED IMPORTED_TARGET GLOBAL libpsl)
endif()

add_library(maillookalike STATIC src/psl.cc src/text.cc src/url.cc src/links.cc src/lookalike.cc)
add_library(maillookalike::maillookalike ALIAS maillookalike)
target_include_directories(maillookalike PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(maillookalike PUBLIC cxx_std_20)
target_link_libraries(maillookalike PRIVATE PkgConfig::ICU PkgConfig::PSL)

if(PROJECT_IS_TOP_LEVEL)
  set(_strict -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror)
  target_compile_options(maillookalike PRIVATE ${_strict})
  option(MAILLOOKALIKE_FUZZ "Build the libFuzzer targets instead of the tests (clang)" OFF)
  if(MAILLOOKALIKE_FUZZ)
    target_compile_options(maillookalike PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all)
    foreach(t url_links lookalike_host)
      add_executable(fuzz_${t} fuzz/fuzz_${t}.cc)
      target_link_libraries(fuzz_${t} PRIVATE maillookalike PkgConfig::ICU)
      target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
      target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
      target_compile_definitions(fuzz_${t} PRIVATE MAILLOOKALIKE_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
    endforeach()
  else()
    find_package(GTest REQUIRED)
    enable_testing()
    include(GoogleTest)
    foreach(t psl url links lookalike chromium)
      add_executable(${t}_test tests/${t}_test.cc)
      target_link_libraries(${t}_test PRIVATE maillookalike GTest::gtest_main)
      target_compile_options(${t}_test PRIVATE ${_strict})
      target_compile_definitions(${t}_test PRIVATE MAILLOOKALIKE_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/tests/data"
                                                   MAILLOOKALIKE_TEST_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")
      gtest_discover_tests(${t}_test)
    endforeach()
  endif()
endif()
