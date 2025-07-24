#!/bin/bash

# TTY Debug Tool Build Script

BUILD_DIR="build"
BUILD_TYPE="Release"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            echo "Cleaning build directory..."
            rm -rf "$BUILD_DIR"
            exit 0
            ;;
        --install)
            echo "Installing tty-debug..."
            if [ ! -d "$BUILD_DIR" ]; then
                echo "Error: Build directory not found. Please build first."
                exit 1
            fi
            cd "$BUILD_DIR"
            sudo make install
            exit 0
            ;;
        --help)
            echo "TTY Debug Tool Build Script"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --debug     Build in debug mode"
            echo "  --clean     Clean build directory"
            echo "  --install   Install to system"
            echo "  --help      Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "TTY Debug Tool - CMake Build"
echo "============================="
echo "Build type: $BUILD_TYPE"
echo ""

# Create build directory
if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

# Configure and build
cd "$BUILD_DIR"

echo "Configuring with CMake..."
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..

if [ $? -ne 0 ]; then
    echo "Error: CMake configuration failed"
    exit 1
fi

echo ""
echo "Building..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "Error: Build failed"
    exit 1
fi

echo ""
echo "Build completed successfully!"
echo "Executable: $BUILD_DIR/tty-debug"
echo ""
echo "To run: cd $BUILD_DIR && sudo ./tty-debug"
echo "To install: ./build.sh --install"
