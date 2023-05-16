# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-core)

set(
        CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/lib
)

include_directories(
        include
        ../ccn-iribu-pkt/include
        ../ccn-iribu-fwd/include
        ../ccn-iribu-unix/include
        ../ccn-iribu-test/include
        ../ccn-iribu-utils/include
)

if (DEFINED CCN_IRIBU_RIOT)
    include_directories(
            include
            ../ccn-iribu-riot/include
    )
endif ()

file(
        GLOB
        SOURCES
        "src/*.c"
)

file(
        GLOB
        HEADERS
        "include/*.h"
)

add_library(
        ${PROJECT_NAME}
        STATIC
        ${SOURCES}
        ${HEADERS}
)





