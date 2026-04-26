cmake_minimum_required(VERSION 3.15)
project(CovertChannelEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find Python and pybind11
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG)

if(NOT pybind11_FOUND)
    message(STATUS "pybind11 not found via CMake, trying pip install location")
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import pybind11; print(pybind11.get_cmake_dir())"
        OUTPUT_VARIABLE pybind11_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    find_package(pybind11 CONFIG PATHS ${pybind11_DIR})
endif()

# Source files
set(ENGINE_SOURCES
    src/cwnd_detector.cpp
    src/qos_detector.cpp
    src/cwnd_fingerprinting.cpp
    src/cross_flow_correlation.cpp
    src/zero_day_detector.cpp
    src/simd_statistics.cpp
    src/adversarial_defense.cpp
    src/protocol_agnostic.cpp
    src/bindings.cpp
)

# Create Python module
pybind11_add_module(covert_engine ${ENGINE_SOURCES})

target_include_directories(covert_engine PRIVATE include)

# Compiler optimizations
if(MSVC)
    target_compile_options(covert_engine PRIVATE /O2 /W4 /arch:AVX2)
else()
    target_compile_options(covert_engine PRIVATE -O3 -Wall -Wextra -mavx2)
endif()

# Install
install(TARGETS covert_engine DESTINATION ${CMAKE_INSTALL_PREFIX})
