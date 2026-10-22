cmake_minimum_required(VERSION 3.20)
project(saslik_licensing VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_library(saslik_licensing STATIC src/licensing.cpp)
target_include_directories(saslik_licensing PUBLIC include)
target_link_libraries(saslik_licensing PUBLIC OpenSSL::Crypto)
target_compile_options(saslik_licensing PRIVATE -Wall -Wextra -Wpedantic)

add_executable(saslik-licensingd src/daemon.cpp)
target_link_libraries(saslik-licensingd PRIVATE saslik_licensing)
target_compile_options(saslik-licensingd PRIVATE -Wall -Wextra -Wpedantic)

add_executable(saslik-licensectl src/licensectl.cpp)
target_link_libraries(saslik-licensectl PRIVATE saslik_licensing)
target_compile_options(saslik-licensectl PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
  add_executable(licensing-tests tests/licensing_tests.cpp)
  target_link_libraries(licensing-tests PRIVATE saslik_licensing)
  add_test(NAME licensing-tests COMMAND licensing-tests)
endif()

install(TARGETS saslik-licensingd saslik-licensectl RUNTIME DESTINATION bin)
install(FILES packaging/saslik-licensing.service DESTINATION lib/systemd/system)

