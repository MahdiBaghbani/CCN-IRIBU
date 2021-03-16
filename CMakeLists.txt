########################################################################
# Setup project
########################################################################

# CMake version.
cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

# Project name.
project(ccn-iribu-project
        VERSION 0.0.1
        LANGUAGES C
        DESCRIPTION "CCN-IRIBU is a reduced version of CCN-Lite and focused on NDN protocols."
        )

enable_testing()

add_subdirectory(src)
add_subdirectory(test)
