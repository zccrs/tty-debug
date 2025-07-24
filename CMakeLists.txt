cmake_minimum_required(VERSION 3.16)
project(tty-debug VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -D_GNU_SOURCE")

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -DDEBUG")

# Release flags
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -DNDEBUG")

# Source files
set(SOURCES
    tty-debug.c
)

# Create executable
add_executable(tty-debug ${SOURCES})

# Install target
install(TARGETS tty-debug
    RUNTIME DESTINATION bin
)

# Custom targets
add_custom_target(show-help
    COMMAND ${CMAKE_COMMAND} -E echo "Available targets:"
    COMMAND ${CMAKE_COMMAND} -E echo "  all       - Build the program (default)"
    COMMAND ${CMAKE_COMMAND} -E echo "  clean     - Remove build files"
    COMMAND ${CMAKE_COMMAND} -E echo "  install   - Install to system"
    COMMAND ${CMAKE_COMMAND} -E echo "  show-help - Show this help message"
    VERBATIM
)

# Print build information
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
