cmake_minimum_required(VERSION 3.19)
project(galgame_extractor_host LANGUAGES CXX)

# The 7-Zip SDK backend. The embedding project supplies the target through
# this variable; the default matches the vcpkg "7zip" port (7zip::7zip),
# which compiles the official SDK sources on every supported platform
# (Windows, Linux, macOS, iOS, Android). The bundled
# cmake/AetherSevenZipSdk.cmake module is the alternative for standalone
# builds. libarchive is deliberately not supported as a backend.
set(HRD_SEVENZIP_TARGET "7zip::7zip" CACHE STRING
    "7-Zip SDK library target that provides CreateObject and the format handlers")

if(NOT TARGET "${HRD_SEVENZIP_TARGET}")
    message(FATAL_ERROR
        "GalgameExtractor host engine requires the 7-Zip SDK target "
        "'${HRD_SEVENZIP_TARGET}'. Provide it through vcpkg "
        "(find_package(7zip CONFIG REQUIRED)) or the bundled "
        "cmake/AetherSevenZipSdk.cmake module. libarchive is not a supported "
        "backend.")
endif()

add_library(hrd_host STATIC
    src/abi.cpp
    src/engine.cpp
    src/password.cpp
    src/sevenzip_backend.cpp
    src/sniffer.cpp
    src/volumes.cpp
)
add_library(GalgameExtractor::hrd_host ALIAS hrd_host)

target_compile_features(hrd_host PUBLIC cxx_std_17)
# HRD_STATIC selects the static (non-dllimport) ABI flavor of include/hrd.h
# for this library and every consumer of the public header.
target_compile_definitions(hrd_host PUBLIC HRD_STATIC=1)
target_include_directories(hrd_host
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# The 7-Zip SDK registers format handlers and codecs through static
# initializers, so the final link must keep every SDK object (whole-archive).
target_link_libraries(hrd_host
    PUBLIC
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,${HRD_SEVENZIP_TARGET}>"
)
if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(hrd_host PUBLIC Threads::Threads)
endif()

option(HRD_HOST_BUILD_TESTS
    "Build the GalgameExtractor real-sample tests" OFF)
if(HRD_HOST_BUILD_TESTS)
    enable_testing()
    add_executable(hrd_sample_tests tests/hrd_sample_tests.cpp)
    target_compile_features(hrd_sample_tests PRIVATE cxx_std_17)
    target_link_libraries(hrd_sample_tests PRIVATE hrd_host)
    add_test(NAME hrd_sample_tests
        COMMAND hrd_sample_tests
            "${CMAKE_CURRENT_SOURCE_DIR}/../test_samples"
            "${CMAKE_CURRENT_BINARY_DIR}/hrd-test-work")
endif()
