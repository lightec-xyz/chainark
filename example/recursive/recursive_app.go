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
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./recursive --setup")
		fmt.Println("usage: ./recursive -g genesisProofFile unitProofFile Id2 Id3")     // the chain is: (genesis, ID1, ID2), ID3, ID4...
		fmt.Println("usage: ./recursive -r recursiveProofFile unitProofFile Idn Idn+1") // note that genesis ID is implied in both cases
		return
	}

	recursiveUnitVkey, ccsGenesis, ccsUnit := example.CreateGenesisObjects()

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

		UnitVKeyFpBytes: example.GetUnitFpBytes(),
		GenesisFpBytes:  example.GetGenesisFpBytes(),
		InnerField:      ecc.BN254.ScalarField(),
	}

	ccsRecursive, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &recursive)
	if err != nil {
		panic(err)
	}

	if strings.Compare(os.Args[1], "--setup") == 0 {
		fmt.Println("setting up... ")

		scs := ccsRecursive.(*cs.SparseR1CS)

		srs, srsLagrange, err := unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
		if err != nil {
			panic(err)
		}
		pk, vk, err := plonk.Setup(ccsRecursive, srs, srsLagrange)
		if err != nil {
			panic(err)
		}

		pkFile, err := os.Create(example.RecursivePkeyFile)
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		vkFile, err := os.Create(example.RecursiveVkeyFile)
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		fmt.Println("saved pkey and vkey")
		return
	}

	idHexLen := example.IDLength * example.LinkageIDBitsPerElement * 2 / 8
	if len(os.Args) < 6 || len(os.Args[4]) != idHexLen || len(os.Args[5]) != idHexLen {
		fmt.Println("usage: ./recursive -g genesisProofFile unitProofFile Id2 Id3\nNote that the Id is some value of SHA256, thus 32 bytes.")
		fmt.Println("usage: ./recursive -r recursiveProofFile unitProofFile Idn Idn+1")
		return
	}

	firstProofFileName := os.Args[2]
	secondProofFileName := os.Args[3]
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

	id1Hex := os.Args[4]
	id1Bytes := make([]byte, len(id1Hex)/2)
	id2Hex := os.Args[5]
	id2Bytes := make([]byte, len(id2Hex)/2)
	hex.Decode(id1Bytes, []byte(id1Hex))
	hex.Decode(id2Bytes, []byte(id2Hex))

	genesisID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](example.GetGenesisIdBytes(), example.LinkageIDBitsPerElement)
	firstID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](id1Bytes, example.LinkageIDBitsPerElement)
	secondID := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](id2Bytes, example.LinkageIDBitsPerElement)

	var firstAssignment frontend.Circuit
	var firstVkeyFileName string
	selector := string(os.Args[1])
	if strings.EqualFold(selector, "-g") {
		firstVkeyFileName = "../genesis/genesis.vkey"
		firstAssignment = &chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			AcceptableFirstFp: chainark.FingerPrintFromBytes[sw_bn254.ScalarField](example.GetRecursiveFpBytes(), example.FingerPrintBitsPerElement),
			GenesisID:         genesisID,
			SecondID:          firstID,
		}
	} else {
		firstVkeyFileName = "recursive.vkey"
		firstAssignment = &chainark.RecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			AcceptableFirstFp: chainark.FingerPrintFromBytes[sw_bn254.ScalarField](example.GetRecursiveFpBytes(), example.FingerPrintBitsPerElement),
			BeginID:           genesisID,
			EndID:             firstID,
		}
	}
	firstWitness, err := frontend.NewWitness(firstAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
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

	fmt.Println("loading first verification key from ", firstVkeyFileName)
	firstVkeyFile, err := os.Open(firstVkeyFileName)
	if err != nil {
		panic(err)
	}
	firstVkey := plonk.NewVerifyingKey(ecc.BN254)
	firstVkey.ReadFrom(firstVkeyFile)
	firstVkeyFile.Close()

	// let's make sure that the first set of vkey/witness/proof checks out
	fmt.Println("verifying first proof natively...")
	err = plonk.Verify(firstProof, firstVkey, firstWitness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	// proceed to recursive verification

	firstRecursiveWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](firstWitness)
	if err != nil {
		panic(err)
	}
	secondRecursiveWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](secondWitness)
	if err != nil {
		panic(err)
	}
	recursiveFirstVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](firstVkey)
	if err != nil {
		panic(err)
	}

	w := chainark.RecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		FirstVKey:         recursiveFirstVkey,
		FirstProof:        firstRecursiveProof,
		AcceptableFirstFp: chainark.FingerPrintFromBytes[sw_bn254.ScalarField](example.GetRecursiveFpBytes(), example.FingerPrintBitsPerElement),

		SecondVKey:  recursiveUnitVkey,
		SecondProof: secondRecursiveProof,

		BeginID: genesisID,
		RelayID: firstID,
		EndID:   secondID,

		FirstWitness:  firstRecursiveWitness,
		SecondWitness: secondRecursiveWitness,
	}
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	pubWitness, err := witness.Public()

	fmt.Println("loading keys ...")
	pkey := plonk.NewProvingKey(ecc.BN254)
	vkey := plonk.NewVerifyingKey(ecc.BN254)

	pkFile, err := os.Open(example.RecursivePkeyFile)
	if err != nil {
		panic(err)
	}
	pkey.ReadFrom(pkFile)
	pkFile.Close()

	vkFile, err := os.Open(example.RecursiveVkeyFile)
	if err != nil {
		panic(err)
	}
	vkey.ReadFrom(vkFile)
	vkFile.Close()

	fmt.Println("proving ...")
	proof, err := plonk.Prove(ccsRecursive, pkey, witness,
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

	proofFile, err := os.Create(example.RecursiveProofFile)
	if err != nil {
		panic(err)
	}
	proof.WriteTo(proofFile)
	proofFile.Close()
	fmt.Println("saved proof")
}
