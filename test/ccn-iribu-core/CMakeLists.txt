# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-core-tests)

set(
        CMAKE_RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/test/ccn-iribu-core
)

set(
        CCN_IRIBU_EXTRA_FLAGS
        -DUSE_IPV4
        -DUSE_IPV6
)

add_definitions(${CCN_IRIBU_EXTRA_FLAGS})

link_directories(${CMAKE_BINARY_DIR}/lib)

include_directories(
        include
        ../../src/ccn-iribu-pkt/include
        ../../src/ccn-iribu-fwd/include
        ../../src/ccn-iribu-core/include
        ../../src/ccn-iribu-unix/include
)

add_executable(
        test_interest
        test_interest.c
)
target_link_libraries(
        test_interest
        ccn-iribu-core
        ccn-iribu-pkt
        cmocka
)
target_link_libraries(
        test_interest
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_interest
        test_interest
)

add_executable(
        test_sockunion
        test_sockunion.c
)
target_link_libraries(
        test_sockunion
        ccn-iribu-core
        cmocka
)

target_link_libraries(
        test_sockunion
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_sockunion
        test_sockunion
)

add_executable(
        test_producer
        test_producer.c
)
target_link_libraries(
        test_producer
        ccn-iribu-core
        cmocka
)
target_link_libraries(
        test_producer
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_producer
        test_producer
)

add_executable(
        test_pkt-util
        test_pkt-util.c
)
target_link_libraries(
        test_pkt-util
        ccn-iribu-core
        ccn-iribu-pkt
        ccn-iribu-fwd
        cmocka
)
target_link_libraries(
        test_pkt-util
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_pkt-util
        test_pkt-util
)

add_executable(
        test_content
        test_content.c
)
target_link_libraries(
        test_content
        ccn-iribu-core
        ccn-iribu-pkt
        cmocka
)
target_link_libraries(
        test_content
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_content
        test_content
)

add_executable(
        test_prefix
        test_prefix.c
)
target_link_libraries(
        test_prefix
        ccn-iribu-core
        ccn-iribu-fwd
        ccn-iribu-pkt
        ccn-iribu-unix
        cmocka
)
target_link_libraries(
        test_prefix
        ${PROJECT_LINK_LIBS}
        ${EXT_LINK_LIBS}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
)
add_test(
        test_prefix
        test_prefix
)
