package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
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

	recursiveUnitVkey, genesisIdBytes, unitFpBytes, ccsGenesis, _ := example.CreateGenesisObjects()

	if strings.Compare(os.Args[1], "--setup") == 0 {
		fmt.Println("setting up... ")

		scs := ccsGenesis.(*cs.SparseR1CS)

		// let's generate the files again
		srs, srsLagrange, err := unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
		if err != nil {
			panic(err)
		}
		pk, vk, err := plonk.Setup(ccsGenesis, srs, srsLagrange)
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

	genesisID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](genesisIdBytes, example.LinkageIDBitsPerElement)
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
	proof, err := plonk.Prove(ccsGenesis, pkey, witness,
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
