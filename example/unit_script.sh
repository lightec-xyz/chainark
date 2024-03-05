#!/bin/bash

# ensure that the application is newly built
go build .

./example 18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f 7b0131a1805090b69f8235628bb934a56395f6e4ef82c1c6f0e5d1c048d649f9
mv unit.proof unit.1.proof

./example 7b0131a1805090b69f8235628bb934a56395f6e4ef82c1c6f0e5d1c048d649f9 d644b6a32154d8709814eb1b392d630dcadebeac6c78d23c9ea64b42ca050b46
mv unit.proof unit.2.proof

./example d644b6a32154d8709814eb1b392d630dcadebeac6c78d23c9ea64b42ca050b46 9c8a67cbfaac724f168293d09425e67daf506afd0c2412fc5cbd1707643f1625
mv unit.proof unit.3.proof

./example 9c8a67cbfaac724f168293d09425e67daf506afd0c2412fc5cbd1707643f1625 428f6234f06f209042eaa1c4114ddbf42b46863bac343165c383163ab30d2cae
mv unit.proof unit.4.proof

./example 428f6234f06f209042eaa1c4114ddbf42b46863bac343165c383163ab30d2cae d9d88c7cd8d017cbd9bddb18d2685a234d41b5c74ce3f6e32cb79dd9d6b70a84
mv unit.proof unit.5.proof

./example d9d88c7cd8d017cbd9bddb18d2685a234d41b5c74ce3f6e32cb79dd9d6b70a84 db2972cd753b5a07850bf3528a3019d2180fdadc3475b7ebd887bb1636988209
mv unit.proof unit.6.proof
