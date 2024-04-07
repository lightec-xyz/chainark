#!/bin/bash

# ensure that the application is newly built
go build .

export unitFp=$(cat ../fp/unit.fp)
export genesisFp=$(cat ../fp/genesis.fp)
export recursiveFp=$(cat ../fp/recursive.fp)

./recursive prove $unitFp $genesisFp $recursiveFp -g ../genesis/genesis.proof ../unit/unit.3.proof 7a305549229bd0e4c385f35f7905237139d9b2c6fd572422f1fef7aa974365da d9704f606cebeeb8ab1be193a157641cca5d8faa54f7b02ea40077ef96a4f1f2
mv recursive.proof recursive.3.proof

./recursive prove $unitFp $genesisFp $recursiveFp -r recursive.3.proof ../unit/unit.4.proof d9704f606cebeeb8ab1be193a157641cca5d8faa54f7b02ea40077ef96a4f1f2 d22d03e3c9edd2c5ef8c946d17347483ff9d893955106e9b9330d6081e45d422
mv recursive.proof recursive.4.proof

./recursive prove $unitFp $genesisFp $recursiveFp -r recursive.4.proof ../unit/unit.5.proof d22d03e3c9edd2c5ef8c946d17347483ff9d893955106e9b9330d6081e45d422 0d0d126303de06698b30a7dcef5390dc3b8b451b2a24102f1f9646aa7102fa13
mv recursive.proof recursive.5.proof

./recursive prove $unitFp $genesisFp $recursiveFp -r recursive.5.proof ../unit/unit.6.proof 0d0d126303de06698b30a7dcef5390dc3b8b451b2a24102f1f9646aa7102fa13 a1ac83d0e18e0845ced8bcd71be011c011c8cde038b3aa98e4407fe5584acd7e
mv recursive.proof recursive.6.proof
