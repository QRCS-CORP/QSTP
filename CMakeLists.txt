cmake_minimum_required(VERSION 3.15)

project(QSTP_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# QSTP Static Library
file(GLOB_RECURSE QSTP_SOURCES "Source/QSTP/*.c")
file(GLOB_RECURSE QSTP_HEADERS "Source/QSTP/include/*.h")

add_library(qstp STATIC ${QSTP_SOURCES} ${QSTP_HEADERS})
target_include_directories(qstp PUBLIC "Source/QSTP")
target_link_libraries(qstp PUBLIC qsc)

# QSTP Client
file(GLOB_RECURSE QSTP_CLIENT_SOURCES "Source/Client/*.c")

add_executable(qstp_client ${QSTP_CLIENT_SOURCES})
target_include_directories(qstp_client PRIVATE "Source/Client")
target_link_libraries(qstp_client PRIVATE qstp)

# QSTP Server
file(GLOB_RECURSE QSTP_SERVER_SOURCES "Source/Server/*.c")

add_executable(qstp_server ${QSTP_SERVER_SOURCES})
target_include_directories(qstp_server PRIVATE "Source/Server")
target_link_libraries(qstp_server PRIVATE qstp)

# QSTP Root
file(GLOB_RECURSE QSTP_ROOT_SOURCES "Source/Root/*.c")

add_executable(qstp_root ${QSTP_ROOT_SOURCES})
target_include_directories(qstp_root PRIVATE "Source/Root")
target_link_libraries(qstp_root PRIVATE qstp)

# Warnings -Werror
foreach(target qstp qstp_client qstp_server qstp_root)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endforeach()
