module github.com/lightec-xyz/chainark

go 1.20

require github.com/consensys/gnark v0.9.1
require github.com/consensys/gnark-crypto v0.12.2-0.20240215234832-d72fcb379d3e

replace github.com/consensys/gnark => ../gnark

replace github.com/consensys/gnark-crypto => ../gnark-crypto
