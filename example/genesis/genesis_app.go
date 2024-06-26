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
	if len(os.Args) < 3 {
		fmt.Println("usage: ./genesis setup $unitFp")
		fmt.Println("usage: ./genesis prove $unitFp $recursiveFp firstProofFile secondProofFile Id1 Id2")
		return
	}

	unitFp := example.GetFpBytes(os.Args[2])
	recursiveUnitVkey := example.LoadUnitVkey()
	ccsUnit := example.NewUnitCcs()
	ccsGenesis := example.NewGenesisCcs(ccsUnit, unitFp)

	if strings.EqualFold(os.Args[1], "setup") {
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
	if len(os.Args) < 8 || len(os.Args[6]) != idHexLen || len(os.Args[7]) != idHexLen {
		fmt.Println("usage: ./genesis prove $unitFp $recursiveFp firstProofFile secondProofFile Id1 Id2\nNote that the Id is some value of SHA256, thus 32 bytes.")
		return
	}

	recursiveFp := example.GetFpBytes(os.Args[3])

	firstProofFileName := os.Args[4]
	secondProofFileName := os.Args[5]
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

	id1Hex := os.Args[6]
	id1Bytes := make([]byte, len(id1Hex)/2)
	id2Hex := os.Args[7]
	id2Bytes := make([]byte, len(id2Hex)/2)
	hex.Decode(id1Bytes, []byte(id1Hex))
	hex.Decode(id2Bytes, []byte(id2Hex))

	genesisID := chainark.LinkageIDFromBytes(example.GetGenesisIdBytes(), example.LinkageIDBitsPerElement)
	firstID := chainark.LinkageIDFromBytes(id1Bytes, example.LinkageIDBitsPerElement)
	secondID := chainark.LinkageIDFromBytes(id2Bytes, example.LinkageIDBitsPerElement)

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

	w := chainark.NewGenesisAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		recursiveUnitVkey, firstRecursiveProof, secondRecursiveProof, firstRecursiveWitness, secondRecursiveWitness,
		chainark.FingerPrintFromBytes(recursiveFp, example.FingerPrintBitsPerElement),
		genesisID, firstID, secondID)
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	pubWitness, err := witness.Public()

	// simulation
	// genesis := chainark.NewGenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
	// 	example.IDLength, example.LinkageIDBitsPerElement, example.FpLength, example.FingerPrintBitsPerElement,
	// 	ccsUnit, example.GetUnitFpBytes())
	// err = test.IsSolved(genesis, &w, ecc.BN254.ScalarField())
	// if err != nil {
	// 	panic(err)
	// }

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
