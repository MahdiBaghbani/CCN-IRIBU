# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu)

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_SYSTEM_NAME Generic)

option(
        BUILD_TESTING
        "Build the testing tree."
        ON
)

option(
        CCN_IRIBU_RIOT
        "Build for RIOT."
        OFF
)

option(
        CCN_IRIBU_PACKETFORMAT_NDN
        "Use the NDN (v0.2) packet parser."
        ON
)

option(
        CCN_IRIBU_PACKETFORMAT_CCNB
        "Use the CCNb packet parser."
        ON
)

option(
        CCN_IRIBU_PACKETFORMAT_CCNTLV
        "Use the CCNTLV packet parser."
        ON
)

option(
        CCN_IRIBU_PACKETFORMAT_LOCALRPC
        "Use localrpc."
        ON
)

if (CCN_IRIBU_RIOT)
    set(CCN_IRIBU_PACKETFORMAT_CCNB OFF)
    set(CCN_IRIBU_PACKETFORMAT_CCNTLV OFF)
    set(CCN_IRIBU_PACKETFORMAT_LOCALRPC OFF)
endif ()

# CCN_IRIBU flags
set(CCN_IRIBU_BASIC_FLAGS
        -DUSE_DEBUG
        -DUSE_LOGGING
        #    -DUSE_SIGNATURES
        -DUSE_DUP_CHECK
        #    -DUSE_ECHO
        -DUSE_HMAC256
        -DUSE_STATS
        -DNEEDS_PACKET_CRAFTING
        -DNEEDS_PREFIX_MATCHING
        -DUSE_LINKLAYER
        CACHE PATH
        "basic build flags for CNN-IRIBU"
        )

add_definitions(${CCN_IRIBU_BASIC_FLAGS})

if (NOT CCN_IRIBU_RIOT)
    set(
            CCN_IRIBU_EXTRA_FLAGS
            -DUSE_CCNxDIGEST
            -DUSE_MGMT
            -DUSE_UNIXSOCKET
            -DUSE_IPV4
            -DUSE_IPV6
            -DUSE_DEBUG_MALLOC
            -DUSE_HTTP_STATUS
    )

    add_definitions(${CCN_IRIBU_EXTRA_FLAGS})
endif ()

# Platforms
set(CCN_IRIBU_PLATFORM_FLAGS
        -DCCN_IRIBU_UNIX
        #    -DCCN_IRIBU_ARDUINO
        CACHE PATH
        "platform flags for CNN-IRIBU"
        )
add_definitions(${CCN_IRIBU_PLATFORM_FLAGS})

# Packet formats
set(CCN_IRIBU_PACKETFORMAT_FLAGS "")

if (CCN_IRIBU_PACKETFORMAT_NDN)
    set(
            CCN_IRIBU_PACKETFORMAT_FLAGS
            "${CCN_IRIBU_PACKETFORMAT_FLAGS}"
            -DUSE_SUITE_NDNTLV
    )
endif ()

if (CCN_IRIBU_PACKETFORMAT_CCNB)
    set(
            CCN_IRIBU_PACKETFORMAT_FLAGS
            "${CCN_IRIBU_PACKETFORMAT_FLAGS}"
            -DUSE_SUITE_CCNB
    )
endif ()

if (CCN_IRIBU_PACKETFORMAT_CCNTLV)
    set(
            CCN_IRIBU_PACKETFORMAT_FLAGS
            "${CCN_IRIBU_PACKETFORMAT_FLAGS}"
            -DUSE_SUITE_CCNTLV
    )
endif ()

if (CCN_IRIBU_PACKETFORMAT_LOCALRPC)
    set(
            CCN_IRIBU_PACKETFORMAT_FLAGS
            "${CCN_IRIBU_PACKETFORMAT_FLAGS}"
            -DUSE_SUITE_LOCALRPC)
endif ()

set(
        "${CCN_IRIBU_PACKETFORMAT_FLAGS}"
        CACHE
        PATH
        "packet format flags for CNN-IRIBU"
)

add_definitions(${CCN_IRIBU_PACKETFORMAT_FLAGS})

if (CCN_IRIBU_RIOT)
    set(CCN_IRIBU_RIOT_FLAGS
            -DCCN_IRIBU_APP_RX
            -DUSE_DUP_CHECK
            ${RIOT_CFLAGS}
            CACHE PATH
            "CCN_IRIBU RIOT flags for CNN-IRIBU"
            )
    add_definitions(${CCN_IRIBU_RIOT_FLAGS})
endif ()

if (NOT CCN_IRIBU_RIOT)
    set(
            CMAKE_C_FLAGS
            "${CMAKE_C_FLAGS} -Wextra -Wall -Werror -std=c99 -g -pedantic"
    ) #TODO: add -fsanitize=address
else ()
    set(
            CMAKE_C_FLAGS
            "${CMAKE_C_FLAGS} -Wextra -Wall -Werror -std=c99 -g"
    )
endif ()

set(
        CMAKE_C_FLAGS_DEBUG
        "${CMAKE_C_FLAGS} -g"
)

if (NOT DEFINED CCN_IRIBU_LINUXKERNEL AND NOT CCN_IRIBU_RIOT)
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif ()

#add_subdirectory(ccn-iribu-addons)
#if (CCN_IRIBU_RIOT)
#  set(CMAKE_C_FLAGS ${RIOT_CFLAGS})
#endif()

if (NOT DEFINED CCN_IRIBU_LINUXKERNEL)
    add_subdirectory(ccn-iribu-core)
    add_subdirectory(ccn-iribu-pkt)
    add_subdirectory(ccn-iribu-fwd)

    if (NOT CCN_IRIBU_RIOT)
        add_subdirectory(ccn-iribu-unix)
        add_subdirectory(ccn-iribu-relay)
        add_subdirectory(ccn-iribu-utils)
    endif ()
endif ()

if (CCN_IRIBU_RIOT)
    add_subdirectory(ccn-iribu-riot)
endif ()

if (DEFINED CCN_IRIBU_LINUXKERNEL)
    add_subdirectory(ccn-iribu-lnxkernel)
endif ()

if (NOT DEFINED CCN_IRIBU_LINUXKERNEL)
    if (NOT CCN_IRIBU_RIOT)
        add_dependencies(
                ccn-iribu-relay
                ccn-iribu-core
                ccn-iribu-pkt
                ccn-iribu-fwd
                ccn-iribu-unix
        )
    endif ()
endif ()

find_package(Doxygen)
if (DOXYGEN_FOUND)
    set(
            DOXYGEN_IN
            ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in
    )

    set(
            DOXYGEN_OUT
            ${CMAKE_CURRENT_BINARY_DIR}/doc/Doxyfile
    )

    configure_file(
            ${DOXYGEN_IN}
            ${DOXYGEN_OUT}
            @ONLY
    )

    message("Doxygen build started")

    add_custom_target(
            doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
    )
endif ()


# unused:
set(
        CCN_IRIBU_DISABLED_FLAGS
        "USE_LINKLAYER
        USE_DEBUG
        USE_DEBUG_MALLOC
        USE_FRAG
		USE_SCHEDULER
		USE_SIGNATURES"
)
