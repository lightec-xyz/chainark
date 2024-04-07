#!/bin/bash

cd unit
go build .
./unit setup

cd ../fp
go build .
./fp unit >unit.draft
export unitFp=$(./fp.sh unit.draft)
echo $unitFp >unit.fp
rm unit.draft

echo unit circuit fingerprint: $unitFp

cd ../genesis
go build .
./genesis setup $unitFp

cd ../fp
./fp genesis $unitFp >genesis.draft
export genesisFp=$(./fp.sh genesis.draft)
echo $genesisFp>genesis.fp
rm genesis.draft

echo genesis circuit fingerprint: $genesisFp

cd ../recursive
go build .
./recursive setup $unitFp $genesisFp

cd ../fp
./fp recursive $unitFp $genesisFp >recursive.draft
export recursiveFp=$(./fp.sh recursive.draft)
echo $recursiveFp>recursive.fp
rm recursive.draft

echo recursive circuit fingerprint: $recursiveFp
