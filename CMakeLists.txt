cmake_minimum_required(VERSION 3.20)
project(saslik_licensing VERSION 0.1.0 LANGUAGES CXX)

set(SASLIK_CONFIG_DIR "/etc/saslik/licensing" CACHE PATH
    "System directory for Saslik licensing trust configuration")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_library(saslik_licensing STATIC src/licensing.cpp src/dns_key.cpp)
target_include_directories(saslik_licensing PUBLIC include)
target_link_libraries(saslik_licensing PUBLIC OpenSSL::Crypto)
target_compile_options(saslik_licensing PRIVATE -Wall -Wextra -Wpedantic)

add_executable(saslik-licensingd src/daemon.cpp)
target_link_libraries(saslik-licensingd PRIVATE saslik_licensing)
target_compile_options(saslik-licensingd PRIVATE -Wall -Wextra -Wpedantic)

add_executable(saslik-licensectl src/licensectl.cpp)
target_link_libraries(saslik-licensectl PRIVATE saslik_licensing)
target_compile_options(saslik-licensectl PRIVATE -Wall -Wextra -Wpedantic)

add_executable(saslik-license-issuer src/issuer.cpp)
target_link_libraries(saslik-license-issuer PRIVATE saslik_licensing)
target_compile_options(saslik-license-issuer PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
  add_executable(licensing-tests tests/licensing_tests.cpp)
  target_link_libraries(licensing-tests PRIVATE saslik_licensing)
  add_test(NAME licensing-tests COMMAND licensing-tests)
  add_test(
    NAME issuer-tool-tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/issuer_tool_tests.sh
            $<TARGET_FILE:saslik-license-issuer>
            $<TARGET_FILE:saslik-licensectl>
            $<TARGET_FILE:saslik-licensingd>)
  add_test(
    NAME install-layout-tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/install_layout_tests.sh
            ${CMAKE_COMMAND} ${CMAKE_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/keys/saslik-root-public.pem)
endif()

install(TARGETS saslik-licensingd saslik-licensectl saslik-license-issuer
        RUNTIME DESTINATION bin)
install(FILES packaging/saslik-licensing.service DESTINATION lib/systemd/system)
install(FILES packaging/keys/saslik-root-public.pem
        DESTINATION ${SASLIK_CONFIG_DIR}
        RENAME root.pem)
