#!/bin/bash

cd unit
go build .
./unit setup

cd ../genesis
go build .
./genesis setup 

cd ../recursive
go build .
./recursive setup   
