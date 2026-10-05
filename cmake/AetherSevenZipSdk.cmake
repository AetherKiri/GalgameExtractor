cmake_minimum_required(VERSION 3.19)

set(AETHER_7ZIP_SDK_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/7zip-sdk"
    CACHE PATH "7-Zip SDK source root")

set(AETHER_7ZIP_SDK_CPP_ROOT "${AETHER_7ZIP_SDK_ROOT}/CPP")

if(NOT EXISTS "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip/Archive/ArchiveExports.cpp")
    message(FATAL_ERROR "The 7-Zip SDK submodule is missing. Run git submodule update --init --recursive.")
endif()

file(GLOB_RECURSE AETHER_7ZIP_SDK_SOURCES CONFIGURE_DEPENDS
    "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip/Archive/*.cpp"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip/Common/*.cpp"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip/Compress/*.cpp"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip/Crypto/*.cpp"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/Common/*.cpp"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/Windows/*.cpp"
    "${AETHER_7ZIP_SDK_ROOT}/C/*.c"
)

list(FILTER AETHER_7ZIP_SDK_SOURCES EXCLUDE REGEX ".*/DllExports(2)?(Compress)?\\.cpp$")
list(FILTER AETHER_7ZIP_SDK_SOURCES EXCLUDE REGEX ".*/CodecExports\\.cpp$")
list(FILTER AETHER_7ZIP_SDK_SOURCES EXCLUDE REGEX ".*/StdAfx\\.cpp$")
# C/Util contains standalone command-line, installer, uninstaller, and SFX
# programs. Several of those are Windows-only and are not part of the 7-Zip
# extraction library; including them in the recursive C glob breaks Android
# and Apple builds on headers such as ShlObj.h.
list(FILTER AETHER_7ZIP_SDK_SOURCES EXCLUDE REGEX ".*/C/Util/.*\\.c$")

set(AETHER_7ZIP_SDK_WINDOWS_SOURCES)
foreach(_source IN ITEMS
    ErrorMsg.cpp FileDir.cpp FileFind.cpp FileIO.cpp FileLink.cpp FileName.cpp
    FileSystem.cpp PropVariant.cpp PropVariantConv.cpp PropVariantUtils.cpp
    Synchronization.cpp System.cpp TimeUtils.cpp)
    list(APPEND AETHER_7ZIP_SDK_WINDOWS_SOURCES
        "${AETHER_7ZIP_SDK_CPP_ROOT}/Windows/${_source}")
endforeach()
list(FILTER AETHER_7ZIP_SDK_SOURCES EXCLUDE REGEX ".*/Windows/.*\\.cpp$")
list(APPEND AETHER_7ZIP_SDK_SOURCES ${AETHER_7ZIP_SDK_WINDOWS_SOURCES})

add_library(aether_7zip_sdk STATIC ${AETHER_7ZIP_SDK_SOURCES})
target_sources(aether_7zip_sdk PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/AetherSevenZipGuid.cpp")
target_compile_features(aether_7zip_sdk PRIVATE cxx_std_17)
target_compile_definitions(aether_7zip_sdk PRIVATE
    _FILE_OFFSET_BITS=64
)
target_include_directories(aether_7zip_sdk PUBLIC
    "${AETHER_7ZIP_SDK_CPP_ROOT}"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/7zip"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/Common"
    "${AETHER_7ZIP_SDK_CPP_ROOT}/Windows"
    "${AETHER_7ZIP_SDK_ROOT}/C"
    "${AETHER_7ZIP_SDK_ROOT}"
)

if(UNIX)
    target_link_libraries(aether_7zip_sdk PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
elseif(WIN32)
    target_link_libraries(aether_7zip_sdk PUBLIC
        oleaut32 ole32 uuid advapi32 user32 shell32)
endif()

set_target_properties(aether_7zip_sdk PROPERTIES POSITION_INDEPENDENT_CODE ON)
