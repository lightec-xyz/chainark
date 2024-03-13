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
	var genesisVkeyFileName string
	if len(os.Args) == 2 {
		genesisVkeyFileName = os.Args[1]
	} else {
		genesisVkeyFileName = "../genesis/genesis.vkey"
	}

	genesisVkeyFile, err := os.Open(genesisVkeyFileName)
	if err != nil {
		panic(err)
	}
	genesisVkey := plonk.NewVerifyingKey(ecc.BN254)
	genesisVkey.ReadFrom(genesisVkeyFile)
	genesisVkeyFile.Close()

	recursiveGenesisVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](genesisVkey)
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

	genesis := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		UnitVKey:          recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		FirstProof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		SecondProof:       recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		AcceptableFirstFp: chainark.PlaceholderFingerPrint[sw_bn254.ScalarField](example.FpLength, example.FingerPrintBitsPerElement),
		GenesisID:         chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		FirstID:           chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		SecondID:          chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		FirstWitness:      recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),
		SecondWitness:     recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),

		UnitVkeyFpBytes: example.GetUnitFpBytes(),
		GenesisIDBytes:  example.GetGenesisIdBytes(),
		InnerField:      ecc.BN254.ScalarField(),
	}
	ccsGenesis, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &genesis)

	extractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsGenesis),
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
		Vkey: recursiveGenesisVkey,
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
