# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-unix)
 
set(
        CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/lib
)

include_directories(
        include
        ../ccn-iribu-pkt/include
        ../ccn-iribu-fwd/include
        ../ccn-iribu-core/include
        ../ccn-iribu-addons/include
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

add_library(
        ${PROJECT_NAME}
        STATIC
        ${SOURCES}
        ${HEADERS}
)
