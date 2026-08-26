cmake_minimum_required(VERSION 3.20)

project(TenRiffServer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TENRIFF_SERVER_BUILD_TESTS "Build the TenRiff Server tests" ON)
option(TENRIFF_SERVER_ENABLE_ASAN "Enable AddressSanitizer" OFF)
set(TENRIFF_CLIENT_SOURCE_DIR "" CACHE PATH
    "Optional TenRiff client checkout for protocol-v5 cross-repository tests")

if(MSVC)
    add_compile_options(/utf-8 /EHsc /W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

if(TENRIFF_SERVER_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address /Zi)
        add_link_options(/INCREMENTAL:NO)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    else()
        message(FATAL_ERROR "AddressSanitizer is unsupported by this compiler")
    endif()
endif()

add_library(tenriff_server_core
    src/Coordinator.cpp
    src/Protocol.cpp
)
target_include_directories(tenriff_server_core PUBLIC include)

add_library(tenriff_server_net
    src/TcpServer.cpp
)
target_include_directories(tenriff_server_net PUBLIC include)
target_link_libraries(tenriff_server_net PUBLIC tenriff_server_core)

if(WIN32)
    target_link_libraries(tenriff_server_net PUBLIC ws2_32)
endif()

add_executable(tenriff-server src/main.cpp)
target_link_libraries(tenriff-server PRIVATE tenriff_server_net)

install(TARGETS tenriff-server RUNTIME DESTINATION bin)

if(TENRIFF_SERVER_BUILD_TESTS)
    enable_testing()
    add_executable(tenriff_server_tests tests/server_tests.cpp)
    target_link_libraries(tenriff_server_tests PRIVATE tenriff_server_net)
    add_test(NAME tenriff_server_tests COMMAND tenriff_server_tests)
    set_tests_properties(tenriff_server_tests PROPERTIES TIMEOUT 30)

    if(WIN32 AND TENRIFF_CLIENT_SOURCE_DIR AND
       EXISTS "${TENRIFF_CLIENT_SOURCE_DIR}/src/network/PeerSession.cpp")
        add_executable(tenriff_client_compat_tests
            tests/tenriff_client_compat.cpp
            "${TENRIFF_CLIENT_SOURCE_DIR}/src/network/PeerProtocol.cpp"
            "${TENRIFF_CLIENT_SOURCE_DIR}/src/network/PeerSession.cpp"
        )
        target_include_directories(tenriff_client_compat_tests PRIVATE
            "${TENRIFF_CLIENT_SOURCE_DIR}/src"
        )
        target_link_libraries(tenriff_client_compat_tests PRIVATE
            tenriff_server_net
            ws2_32
        )
        add_test(NAME tenriff_client_protocol_v5_compat
                 COMMAND tenriff_client_compat_tests)
        set_tests_properties(tenriff_client_protocol_v5_compat PROPERTIES TIMEOUT 30)
    endif()
endif()

if(TENRIFF_SERVER_ENABLE_ASAN AND MSVC)
    get_filename_component(TENRIFF_SERVER_COMPILER_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(TENRIFF_SERVER_ASAN_RUNTIME
        "${TENRIFF_SERVER_COMPILER_DIR}/clang_rt.asan_dynamic-x86_64.dll")
    set(TENRIFF_SERVER_ASAN_DEBUG_RUNTIME
        "${TENRIFF_SERVER_COMPILER_DIR}/clang_rt.asan_dbg_dynamic-x86_64.dll")
    foreach(target tenriff-server tenriff_server_tests tenriff_client_compat_tests)
        if(TARGET ${target})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${TENRIFF_SERVER_ASAN_RUNTIME}"
                    "$<TARGET_FILE_DIR:${target}>"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${TENRIFF_SERVER_ASAN_DEBUG_RUNTIME}"
                    "$<TARGET_FILE_DIR:${target}>"
            )
        endif()
    endforeach()
endif()
