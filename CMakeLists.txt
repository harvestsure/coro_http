cmake_minimum_required(VERSION 3.20...3.31)
project(coro-http-client CXX)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

if(POLICY CMP0174)
  cmake_policy(SET CMP0174 NEW)
endif()

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

# Try to find ASIO from VCPKG first, fall back to FetchContent
find_package(asio CONFIG QUIET)

if(NOT asio_FOUND)
  # Fallback to FetchContent for local development without VCPKG
  include(FetchContent)
  
  FetchContent_Declare(
      asio
      GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
      GIT_TAG asio-1-30-2
  )
  
  FetchContent_MakeAvailable(asio)
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_library(coro_http INTERFACE)

# Include directories
target_include_directories(coro_http INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Add ASIO includes (from FetchContent if not found via find_package)
if(NOT asio_FOUND)
  target_include_directories(coro_http INTERFACE 
      $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
  )
endif()

target_compile_definitions(coro_http INTERFACE ASIO_STANDALONE)
target_link_libraries(coro_http INTERFACE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

# Link ASIO if found via find_package
if(asio_FOUND)
  target_link_libraries(coro_http INTERFACE asio::asio)
endif()

# Install targets
install(DIRECTORY include/coro_http DESTINATION include)
install(TARGETS coro_http EXPORT coro_httpTargets)
install(EXPORT coro_httpTargets 
  FILE coro_httpTargets.cmake
  NAMESPACE coro_http::
  DESTINATION lib/cmake/coro-http-client)

# Install CMake config files
include(CMakePackageConfigHelpers)
configure_package_config_file(
  cmake/coro_httpConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/coro-http-clientConfig.cmake"
  INSTALL_DESTINATION lib/cmake/coro-http-client
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/coro-http-clientConfigVersion.cmake"
  VERSION 1.0.0
  COMPATIBILITY SameMajorVersion
)

install(FILES 
  "${CMAKE_CURRENT_BINARY_DIR}/coro-http-clientConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/coro-http-clientConfigVersion.cmake"
  DESTINATION lib/cmake/coro-http-client
)

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

# Tests
option(BUILD_TESTS "Build tests" OFF)

if (BUILD_TESTS)
  enable_testing()
  
  # Core functionality tests
  add_executable(test_timeout tests/test_timeout.cpp)
  target_link_libraries(test_timeout PRIVATE coro_http)
  add_test(NAME timeout COMMAND test_timeout TIMEOUT 30)
  
  add_executable(test_redirect tests/test_redirect.cpp)
  target_link_libraries(test_redirect PRIVATE coro_http)
  add_test(NAME redirect COMMAND test_redirect TIMEOUT 30)
  
  add_executable(test_connection_pool tests/test_connection_pool.cpp)
  target_link_libraries(test_connection_pool PRIVATE coro_http)
  add_test(NAME connection_pool COMMAND test_connection_pool TIMEOUT 30)
  
  add_executable(test_error_handling tests/test_error_handling.cpp)
  target_link_libraries(test_error_handling PRIVATE coro_http)
  add_test(NAME error_handling COMMAND test_error_handling TIMEOUT 30)
endif()