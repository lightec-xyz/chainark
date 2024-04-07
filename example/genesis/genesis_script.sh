#!/bin/bash

# ensure that the application is newly built
go build .

export unitFp=$(cat ../fp/unit.fp)
export recursiveFp=$(cat ../fp/recursive.fp)

./genesis prove $unitFp $recursiveFp ../unit/unit.1.proof ../unit/unit.2.proof 8e496c403d06ed9e28c69ee853d498a929809596cc86c71aba7426c967d82df7 7a305549229bd0e4c385f35f7905237139d9b2c6fd572422f1fef7aa974365da


