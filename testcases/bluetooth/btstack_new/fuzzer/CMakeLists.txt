cmake_minimum_required(VERSION 3.13.4)

project("BTFuzz")

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

include_directories(include)

file(GLOB COMMON_SRC        "src/common/*.c")
file(GLOB PROTOCOLS_SRC     "src/protocols/*.c")
file(GLOB BTFUZZ_SRC        "src/*.c")
set(SRC  ${BTFUZZ_SRC} ${COMMON_SRC} ${PROTOCOLS_SRC})


add_executable(btfuzz ${SRC} )