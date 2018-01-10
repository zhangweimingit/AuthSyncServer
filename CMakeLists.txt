# CMake version
cmake_minimum_required (VERSION 2.6)

project(ik_auth_ss) 

# source code
aux_source_directory(./src DIR_SRCS)

# default mode : release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

find_package(Boost REQUIRED COMPONENTS program_options system coroutine context filesystem log log_setup)
find_library(SSL_LIB libssl.a REQUIRED)
find_library(CRYPTO_LIB libcrypto.a REQUIRED)
find_library(MYSQL_CONN_LIB libmysqlcppconn.so REQUIRED)

# compile options
set(CMAKE_CXX_FLAGS "-Wall -std=c++11 -DBOOST_LOG_DYN_LINK -DBOOST_COROUTINES_NO_DEPRECATION_WARNING")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2")

find_package(Threads REQUIRED)

add_executable(ik_auth_ss ${DIR_SRCS})
target_link_libraries(ik_auth_ss
    ${Boost_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SSL_LIB}
    ${CRYPTO_LIB}
    ${MYSQL_CONN_LIB}
    )

# output
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
