#!/bin/bash


cd unit 
sh unit_prove.sh

cd ../genesis
sh genesis_prove.sh

cd ../recursive
sh recursive_prove.sh

cd ..
