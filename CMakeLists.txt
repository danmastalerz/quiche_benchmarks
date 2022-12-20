cmake_minimum_required(VERSION 3.23)
project(quiche_benchmarks)

set(CMAKE_CXX_STANDARD 17)

find_library(QUICHE_LIB NAMES quiche HINTS quiche_lib REQUIRED)
if(QUICHE_LIB)
    message(STATUS "Found quiche library - ${QUICHE_LIB}")
endif()

list(APPEND LIBS ${QUICHE_LIB})
list(APPEND INCLUDE_DIRS quiche_lib)

add_executable(server server.cpp benchmark_entities/benchmark_server.h)
add_executable(client client.cpp benchmark_entities/benchmark_client.h)

target_include_directories(server PRIVATE ${INCLUDE_DIRS})
target_link_libraries(server PRIVATE ${LIBS})

target_include_directories(client PRIVATE ${INCLUDE_DIRS})
target_link_libraries(client PRIVATE ${LIBS})
