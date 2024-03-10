package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

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
	if len(os.Args) < 2 {
		fmt.Println("usage: ./genesis --setup")
		fmt.Println("usage: ./genesis firstProofFile secondProofFile Id1 Id2")
		return
	}

	unit := example.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
	}
	ccsUnit, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unit)

	unitVkeyFileName := "../unit/unit.vkey"
	unitVkeyFile, err := os.Open(unitVkeyFileName)
	if err != nil {
		panic(err)
	}
	unitVkey := plonk.NewVerifyingKey(ecc.BN254)
	unitVkey.ReadFrom(unitVkeyFile)
	unitVkeyFile.Close()

	recursiveUnitVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unitVkey)
	if err != nil {
		panic(err)
	}

	genesisHex := "843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85"
	genesisBytes := make([]byte, len(genesisHex)/2)
	hex.Decode(genesisBytes, []byte(genesisHex))

	// computed with the fp/fp utility, before computing you need to at least compute the verification key for the unit circuit
	unitFpBytes := []byte{14, 9, 195, 26, 127, 145, 104, 124, 132, 144, 108, 96, 177, 171, 84, 192, 151, 161, 68, 45, 17, 136, 213, 223, 127, 9, 165, 217, 35, 10, 253, 27}

	circuit := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		// FIXME UnitVKey should be constant however this leads to segment fault, will check back later. If not resolved will have to add back unit fp bytes
		// UnitVKey:          recursiveUnitVkey, // SECURITY: make it a constant to save constraints, also to fix the vkey
		UnitVKey:          recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		FirstProof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		SecondProof:       recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		AcceptableFirstFp: chainark.PlaceholderFingerPrint[sw_bn254.ScalarField](example.FpLength, example.FingerPrintBitsPerElement),

		GenesisID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		FirstID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),
		SecondID:  chainark.PlaceholderLinkageID[sw_bn254.ScalarField](example.IDLength, example.LinkageIDBitsPerElement),

		FirstWitness:  recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),
		SecondWitness: recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),

		GenesisIDBytes: genesisBytes, // constant as well
		InnerField:     ecc.BN254.ScalarField(),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	if strings.Compare(os.Args[1], "--setup") == 0 {
		fmt.Println("setting up... ")

		scs := ccs.(*cs.SparseR1CS)

		var srs, srsLagrange kzg.SRS

		// let's generate the files again
		srs, srsLagrange, err = unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
		if err != nil {
			panic(err)
		}
		pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			panic(err)
		}

		pkFile, err := os.Create(example.GenesisPkeyFile)
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		vkFile, err := os.Create(example.GenesisVkeyFile)
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		fmt.Println("saved pkey and vkey")
		return
	}

	idHexLen := example.IDLength * example.LinkageIDBitsPerElement * 2 / 8
	if len(os.Args) < 5 || len(os.Args[3]) != idHexLen || len(os.Args[4]) != idHexLen {
		fmt.Println("usage: ./genesis firstProofFile secondProofFile Id1 Id2\nNote that the Id is some value of SHA256, thus 32 bytes.")
		return
	}

	firstProofFileName := os.Args[1]
	secondProofFileName := os.Args[2]
	firstProofFile, err := os.Open(firstProofFileName)
	if err != nil {
		panic(err)
	}
	secondProofFile, err := os.Open(secondProofFileName)
	if err != nil {
		panic(err)
	}
	firstProof := plonk.NewProof(ecc.BN254)
	firstProof.ReadFrom(firstProofFile)
	firstProofFile.Close()
	secondProof := plonk.NewProof(ecc.BN254)
	secondProof.ReadFrom(secondProofFile)
	secondProofFile.Close()

	firstRecursiveProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](firstProof)
	if err != nil {
		panic(err)
	}
	secondRecursiveProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](secondProof)
	if err != nil {
		panic(err)
	}

	id1Hex := os.Args[3]
	id1Bytes := make([]byte, len(id1Hex)/2)
	id2Hex := os.Args[4]
	id2Bytes := make([]byte, len(id2Hex)/2)
	hex.Decode(id1Bytes, []byte(id1Hex))
	hex.Decode(id2Bytes, []byte(id2Hex))

	genesisID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](genesisBytes, example.LinkageIDBitsPerElement)
	firstID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](id1Bytes, example.LinkageIDBitsPerElement)
	secondID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](id2Bytes, example.LinkageIDBitsPerElement)

	firstAssignment := example.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: genesisID,
		EndID:   firstID,
	}
	firstWitness, err := frontend.NewWitness(&firstAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	firstRecursiveWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](firstWitness)
	if err != nil {
		panic(err)
	}
	secondAssignment := example.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: firstID,
		EndID:   secondID,
	}
	secondWitness, err := frontend.NewWitness(&secondAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	secondRecursiveWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](secondWitness)
	if err != nil {
		panic(err)
	}

	w := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		UnitVKey:          recursiveUnitVkey,
		FirstProof:        firstRecursiveProof,
		SecondProof:       secondRecursiveProof,
		AcceptableFirstFp: chainark.FingerPrintFromBytes[sw_bn254.ScalarField](unitFpBytes, example.FingerPrintBitsPerElement),

		GenesisID: genesisID,
		FirstID:   firstID,
		SecondID:  secondID,

		FirstWitness:  firstRecursiveWitness,
		SecondWitness: secondRecursiveWitness,
	}
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	pubWitness, err := witness.Public()

	fmt.Println("loading keys ...")
	pkey := plonk.NewProvingKey(ecc.BN254)
	vkey := plonk.NewVerifyingKey(ecc.BN254)

	pkFile, err := os.Open(example.GenesisPkeyFile)
	if err != nil {
		panic(err)
	}
	pkey.ReadFrom(pkFile)
	pkFile.Close()

	vkFile, err := os.Open(example.GenesisVkeyFile)
	if err != nil {
		panic(err)
	}
	vkey.ReadFrom(vkFile)
	vkFile.Close()

	fmt.Println("proving ...")
	proof, err := plonk.Prove(ccs, pkey, witness,
		recursive_plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	fmt.Println("verifying ...")
	err = plonk.Verify(proof, vkey, pubWitness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	proofFile, err := os.Create(example.GenesisProofFile)
	if err != nil {
		panic(err)
	}
	proof.WriteTo(proofFile)
	proofFile.Close()
	fmt.Println("saved proof")
}
