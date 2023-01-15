#!/bin/bash

if [ ! -d "bin" ]; then
    mkdir bin
fi
if [ ! -d "build" ]; then
    mkdir build
fi

cd ./bin
rm -rf *
cd ..

cd ./build
rm -rf ./*
cmake ..
make -j$(shell grep -c ^processor /proc/cpuinfo 2>/dev/null)
cd ../bin

mkdir db


