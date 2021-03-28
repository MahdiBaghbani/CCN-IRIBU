# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-utils)

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

# set include directories
include_directories(
        include
        ../ccn-iribu-pkt/include
        ../ccn-iribu-fwd/include
        ../ccn-iribu-core/include
        ../ccn-iribu-unix/include
)

add_library(
        common
        STATIC
        src/ccn-iribu-common.c
        src/base64.c
        src/ccn-iribu-socket.c
)

add_library(
        ccn-iribu-crypto
        STATIC
        src/ccn-iribu-crypto.c
        src/ccn-iribu-ext-hmac.c
        src/lib-sha256.c
)

add_executable(
        ccn-iribu-peek
        src/ccn-iribu-peek.c
)

#add_executable(ccn-iribu-peekcomputation ccn-iribu-peekcomputation.c) #todo work to do

add_executable(
        ccn-iribu-ctrl
        src/ccn-iribu-ctrl.c
)

add_executable(
        ccn-iribu-fetch
        src/ccn-iribu-fetch.c
)

if (OpenSSL_FOUND)
    add_executable(
            ccn-iribu-ccnb2xml
            src/ccn-iribu-ccnb2xml.c
    )

    add_executable(
            ccn-iribu-cryptoserver
            src/ccn-iribu-cryptoserver.c
    )

    #add_executable(ccn-iribu-deF ccn-iribu-deF.c)

    add_executable(
            ccn-iribu-mkC
            src/ccn-iribu-mkC.c
    )

    add_executable(
            ccn-iribu-valid
            src/ccn-iribu-valid.c
    )

    add_executable(
            ccn-iribu-rpc
            src/ccn-iribu-rpc.c
    )
endif ()

if (USE_FRAG)
    add_executable(
            ccn-iribu-mkF
            src/ccn-iribu-mkF.c
    )
endif ()

add_executable(
        ccn-iribu-mkI
        src/ccn-iribu-mkI.c
)

add_executable(
        ccn-iribu-pktdump
        src/ccn-iribu-pktdump.c
)

add_executable(
        ccn-iribu-produce
        src/ccn-iribu-produce.c
)

target_link_libraries(
        ccn-iribu-peek
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-peek
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
        common
)

#target_link_libraries(ccn-iribu-peekcomputation ${PROJECT_LINK_LIBS} ${EXT_LINK_LIBS})#todo work to do
#target_link_libraries(ccn-iribu-peekcomputation ccn-iribu-core ccn-iribu-pkt ccn-iribu-fwd ccn-iribu-unix)

target_link_libraries(
        ccn-iribu-ctrl
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-ctrl
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
)

if (OpenSSL_FOUND)
    target_link_libraries(
            ccn-iribu-ccnb2xml
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
            ${OPENSSL_LIBRARIES}
    )

    target_link_libraries(
            ccn-iribu-ccnb2xml
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            ${OPENSSL_LIBRARIES}
            common
    )

    target_link_libraries(
            ccn-iribu-cryptoserver
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
            ${OPENSSL_LIBRARIES}
    )

    target_link_libraries(
            ccn-iribu-cryptoserver
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            ${OPENSSL_LIBRARIES}
            common
    )

    #target_link_libraries(ccn-iribu-deF ${PROJECT_LINK_LIBS} ${EXT_LINK_LIBS} ${OPENSSL_LIBRARIES})
    #target_link_libraries(ccn-iribu-deF ccn-iribu-core ccn-iribu-pkt ccn-iribu-fwd ccn-iribu-unix ${OPENSSL_LIBRARIES})

    target_link_libraries(
            ccn-iribu-mkC
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
            ${OPENSSL_LIBRARIES}
            common
    )

    target_link_libraries(
            ccn-iribu-mkC
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            ccn-iribu-crypto
            ${OPENSSL_LIBRARIES}
    )

    target_link_libraries(
            ccn-iribu-valid
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
            ${OPENSSL_LIBRARIES}
            common
            ccn-iribu-crypto
    )

    target_link_libraries(
            ccn-iribu-valid
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            ${OPENSSL_LIBRARIES}
    )

    target_link_libraries(
            ccn-iribu-rpc
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
            ${OPENSSL_LIBRARIES}
            common
    )

    target_link_libraries(
            ccn-iribu-rpc
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            ${OPENSSL_LIBRARIES}
    )
endif ()

target_link_libraries(
        ccn-iribu-fetch
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-fetch
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
        common
)

if (USE_FRAG)
    target_link_libraries(
            ccn-iribu-mkF
            ${PROJECT_LINK_LIBS}
            ${EXT_LINK_LIBS}
    )

    target_link_libraries(
            ccn-iribu-mkF
            ccn-iribu-core
            ccn-iribu-pkt
            ccn-iribu-fwd
            ccn-iribu-unix
            common
    )
endif ()

target_link_libraries(
        ccn-iribu-mkI
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-mkI
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
        common
)

target_link_libraries(
        ccn-iribu-pktdump
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-pktdump
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
        common
)

target_link_libraries(
        ccn-iribu-produce
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
)

target_link_libraries(
        ccn-iribu-produce
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        ccn-iribu-unix
        common
        ccn-iribu-crypto
)
