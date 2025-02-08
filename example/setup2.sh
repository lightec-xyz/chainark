#!/bin/bash

mkdir -p testdata

cd unit
go build .
./unit setup 150

cd ../recursive
go build .
./recursive setup 50

cd ..
