# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-riot)

set(
        CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/lib
)

include_directories(
        include
        ../ccn-iribu-pkt/include
        ../ccn-iribu-fwd/include
        ../ccn-iribu-core/include
        ../ccn-iribu-unix/include
        ../ccn-iribu-utils/include
)

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

file(
        GLOB
        CORESOURCE
        "../ccn-iribu-core/src/*.c"
)

file(
        GLOB
        FWDSOURCE
        "../ccn-iribu-fwd/src/*.c"
)

file(
        GLOB
        PKTSOURCE
        "../ccn-iribu-pkt/src/*.c"
)

add_library(
        ${PROJECT_NAME}
        STATIC
        ${SOURCES}
        ${CORESOURCE}
        ${FWDSOURCE}
        ${PKTSOURCE}
        ${HEADERS}
)
