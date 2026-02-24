cmake_minimum_required(VERSION 3.20)
project(jwt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(jwt INTERFACE)
add_library(jwt::jwt ALIAS jwt)

target_include_directories(jwt INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(jwt INTERFACE /W4 /permissive-)
else()
  target_compile_options(jwt INTERFACE -Wall -Wextra -Wpedantic)
endif()

# --- Vix deps (hmac, hashing) ---
include(.vix/vix_deps.cmake)
target_link_libraries(jwt INTERFACE gaspardkirira::hmac gaspardkirira::hashing)

include(CTest)
enable_testing()

add_executable(jwt_basic_test tests/test_basic.cpp)
target_link_libraries(jwt_basic_test PRIVATE jwt::jwt)
add_test(NAME jwt.basic COMMAND jwt_basic_test)
