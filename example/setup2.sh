#!/bin/bash

mkdir -p testdata

cd unit
go build .
./unit setup 45

cd ../recursive
go build .
./recursive setup 10

cd ..
