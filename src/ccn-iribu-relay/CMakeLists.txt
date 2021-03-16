# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-relay)

set(
        PROJECT_LINK_LIBS
        libccn-iribu-core.a
        libccn-iribu-pkt.a
        libccn-iribu-fwd.a
        libccn-iribu-unix.a
)

set(
        EXT_LINK_LIBS
        ssl
        crypto
)

set(
        CMAKE_RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/bin
)

link_directories(
    ${CMAKE_BINARY_DIR}/lib
)

include_directories(
    ../ccn-iribu-pkt/include
    ../ccn-iribu-fwd/include
    ../ccn-iribu-core/include
    ../ccn-iribu-unix/include
)

file(
        GLOB
        SOURCES
        "*.c"
)

add_executable(
        ${PROJECT_NAME}
        ${SOURCES}
)

target_link_libraries(
        ${PROJECT_NAME}
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-relay
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-core
        ccn-iribu-unix
)
