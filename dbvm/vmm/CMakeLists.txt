cmake_minimum_required(VERSION 3.15)
project(dbvm_user_detect C)

set(CMAKE_C_STANDARD 11)

add_library(dbvm_detect STATIC
  detectors/dbvm_detect.c
)
target_include_directories(dbvm_detect PUBLIC detectors)

if (MSVC)
  target_compile_definitions(dbvm_detect PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(dbvm_detect PRIVATE /W3)
else()
  target_compile_options(dbvm_detect PRIVATE -Wall -Wextra)
endif()

add_executable(dbvm_detect_cli
  detectors/dbvm_detect_cli.c
)
target_link_libraries(dbvm_detect_cli PRIVATE dbvm_detect user32)
