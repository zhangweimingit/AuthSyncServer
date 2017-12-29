#!/bin/bash

if [ "$1" = "make" -a -d "build" ];then
cd build/
make
cd ..
exit 0
fi

rm -rf build/
if [ "$1" = "clean" ];then
    exit 0
fi

# Cross Compiling
CC="gcc"
if [ "$1" = "OpenWrt" ];then
    source ./cmake/openwrt.config
    CC="i486-openwrt-linux-uclibc-gcc"
fi

# cmake
mkdir build
cd build
if [ "$1" = "OpenWrt" -a "$2" = "" ];then
cmake -DCMAKE_TOOLCHAIN_FILE=./cmake/ik_tool_chain.cmake ..
elif [ "$1" = "OpenWrt" -a "$2" = "debug" ];then
cmake -DCMAKE_TOOLCHAIN_FILE=./cmake/ik_tool_chain.cmake -DCMAKE_BUILD_TYPE=Debug ..
elif [ "$1" = "debug" ];then
cmake -DCMAKE_BUILD_TYPE=Debug ..
else
cmake ..
fi

make
