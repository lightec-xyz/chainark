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

cd ../unit 
sh unit_prove.sh

cd ../genesis
sh genesis_prove.sh

cd ../recursive
sh recursive_prove.sh
