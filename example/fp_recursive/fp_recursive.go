package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example"
)

func main() {
	var recursiveVkeyFileName string
	if len(os.Args) == 2 {
		recursiveVkeyFileName = os.Args[1]
	} else {
		recursiveVkeyFileName = "../recursive/recursive.vkey"
	}

	recursiveVkeyFile, err := os.Open(recursiveVkeyFileName)
	if err != nil {
		panic(err)
	}
	recursiveVkey := plonk.NewVerifyingKey(ecc.BN254)
	recursiveVkey.ReadFrom(recursiveVkeyFile)
	recursiveVkeyFile.Close()

	recursiveRecursiveVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](recursiveVkey)
	if err != nil {
		panic(err)
	}

	unit := example.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
	}
	ccsUnit, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unit)
	if err != nil {
		panic(err)
	}

	_, genesisIdBytes, unitFpBytes, ccsGenesis, _ := example.CreateGenesisObjects()
	genesisFpBytes := []byte{133, 239, 51, 63, 8, 199, 118, 72, 84, 162, 76, 39, 204, 248, 9, 95, 220, 161, 208, 111, 188, 23, 171, 170, 104, 152, 161, 245, 194, 245, 177, 8}

	recursive := chainark.RecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		FirstVKey:         recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsGenesis),
		FirstProof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsGenesis),
		AcceptableFirstFp: chainark.PlaceholderFingerPrint[sw_bn254.ScalarField](example.FpLength, example.FingerPrintBitsPerElement),

		SecondVKey:  recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		SecondProof: recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),

		BeginID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		RelayID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),

		FirstWitness:  recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsGenesis),
		SecondWitness: recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),

		UnitVKeyFpBytes: unitFpBytes,
		GenesisFpBytes:  genesisFpBytes,
		GenesisIDBytes:  genesisIdBytes,
	}
	ccsRecursive, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &recursive)

	extractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsRecursive),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &extractor)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)

	var srs, srsLagrange kzg.SRS

	// let's generate the files again
	srs, srsLagrange, err = unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	w := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursiveRecursiveVkey,
	}
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	_, err = plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

}
