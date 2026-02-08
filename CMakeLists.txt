cmake_minimum_required(VERSION 3.20)
project(coro_http CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_SANITIZER "Enable sanitizer" ON)

if (ENABLE_SANITIZER)
  add_compile_options(
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
  )
  add_link_options(
    -fsanitize=address,undefined
  )
endif()

include(FetchContent)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-30-2
)

FetchContent_MakeAvailable(asio)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_library(coro_http INTERFACE)
target_include_directories(coro_http INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(coro_http INTERFACE ASIO_STANDALONE)
target_link_libraries(coro_http INTERFACE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

add_executable(example_coro examples/coro_example.cpp)
target_link_libraries(example_coro PRIVATE coro_http)

add_executable(example_https examples/https_example.cpp)
target_link_libraries(example_https PRIVATE coro_http)

add_executable(example_advanced examples/advanced_example.cpp)
target_link_libraries(example_advanced PRIVATE coro_http)

add_executable(example_proxy examples/proxy_example.cpp)
target_link_libraries(example_proxy PRIVATE coro_http)

add_executable(example_keepalive examples/keepalive_example.cpp)
target_link_libraries(example_keepalive PRIVATE coro_http)

add_executable(example_retry examples/retry_example.cpp)
target_link_libraries(example_retry PRIVATE coro_http)

add_executable(example_auth_features examples/auth_features_example.cpp)
target_link_libraries(example_auth_features PRIVATE coro_http)

add_executable(example_auth_local examples/auth_features_local_test.cpp)
target_link_libraries(example_auth_local PRIVATE coro_http)

add_executable(example_sse_coro examples/sse_coro_example.cpp)
target_link_libraries(example_sse_coro PRIVATE coro_http)