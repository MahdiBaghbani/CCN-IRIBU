# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-pkt)
 
set(
        CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/lib
)

include_directories(
        include
        ../ccn-iribu-fwd/include
        ../ccn-iribu-core/include
)

set(
        SOURCES
        "src/ccn-iribu-pkt-builder.c"
        "src/ccn-iribu-pkt-switch.c"
)

if (CCN_IRIBU_PACKETFORMAT_NDN)
  set(
          SOURCES
          "${SOURCES}"
          "src/ccn-iribu-pkt-ndntlv.c"
  )
endif ()

if (CCN_IRIBU_PACKETFORMAT_CCNTLV)
  set(
          SOURCES
          "${SOURCES}"
          "src/ccn-iribu-pkt-ccntlv.c"
  )
endif ()

if (CCN_IRIBU_PACKETFORMAT_CCNB)
  set(
          SOURCES
          "${SOURCES}"
          "src/ccn-iribu-pkt-ccnb.c"
  )
endif ()

if (CCN_IRIBU_PACKETFORMAT_LOCALRPC)
  set(
          SOURCES
          "${SOURCES}"
          "src/ccn-iribu-pkt-localrpc.c"
  )
endif ()

add_library(
        ${PROJECT_NAME}
        STATIC
        ${SOURCES}
)
