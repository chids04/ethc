cmake_minimum_required(VERSION 3.21)

project(ethc LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(ethc
    main.c
)
target_include_directories(ethc PRIVATE
    src/)
find_package(OpenSSL REQUIRED)

target_compile_options(ethc PRIVATE
    $<$<C_COMPILER_ID:GNU>:-Wall -Wextra>
    $<$<C_COMPILER_ID:Clang>:-Wall -Wextra>
    $<$<C_COMPILER_ID:MSVC>:/W4>
)

target_link_libraries(ethc PUBLIC OpenSSL::SSL OpenSSL::Crypto)
