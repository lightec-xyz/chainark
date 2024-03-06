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
	"github.com/consensys/gnark/std/math/uints"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./genesis --setup")
		fmt.Println("usage: ./genesis firstProofFile secondProofFile Id1 Id2")
		return
	}

	unit := chainark.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: make([]uints.U8, chainark.IDLength),
		EndID:   make([]uints.U8, chainark.IDLength),
	}
	ccsUnit, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unit)

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

	genesisHex := "18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f"
	genesisBytes := make([]byte, len(genesisHex)/2)
	hex.Decode(genesisBytes, []byte(genesisHex))

	// computed with the fp/fp utility, before computing you need to at least compute the verification key for the unit circuit
	unitFpBytes := []byte{228, 106, 40, 72, 122, 77, 90, 241, 36, 48, 48, 55, 97, 230, 185, 69, 39, 17, 21, 178, 24, 234, 142, 148, 165, 162, 194, 144, 37, 174, 143, 12}

	circuit := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		UnitVKey:          recursiveUnitVkey, // SECURITY: make it a constant to save constraints, also to fix the vkey
		FirstProof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		SecondProof:       recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		AcceptableFirstFp: make([]uints.U8, chainark.FpLength),

		GenesisID: make([]uints.U8, chainark.IDLength),
		FirstID:   make([]uints.U8, chainark.IDLength),
		SecondID:  make([]uints.U8, chainark.IDLength),

		UnitFpBytes:    unitFpBytes,  // SECURITY: constant as well
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

		pkFile, err := os.Create(chainark.GenesisPkeyFile)
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		vkFile, err := os.Create(chainark.GenesisVkeyFile)
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		fmt.Println("saved pkey and vkey")
		return
	}

	if len(os.Args) < 5 || len(os.Args[3]) != chainark.IDLength*2 || len(os.Args[4]) != chainark.IDLength*2 {
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

	w := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		// FirstProof: ,//recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](),
		FirstProof:        firstRecursiveProof,
		SecondProof:       secondRecursiveProof,
		AcceptableFirstFp: uints.NewU8Array(unitFpBytes),

		GenesisID: uints.NewU8Array(genesisBytes),
		FirstID:   uints.NewU8Array(id1Bytes),
		SecondID:  uints.NewU8Array(id2Bytes),
	}

	fmt.Println("loading keys ...")
	pkey := plonk.NewProvingKey(ecc.BN254)
	vkey := plonk.NewVerifyingKey(ecc.BN254)

	pkFile, err := os.Open(chainark.GenesisPkeyFile)
	if err != nil {
		panic(err)
	}
	pkey.ReadFrom(pkFile)
	pkFile.Close()

	vkFile, err := os.Open(chainark.GenesisVkeyFile)
	if err != nil {
		panic(err)
	}
	vkey.ReadFrom(vkFile)
	vkFile.Close()

	fmt.Println("proving ...")
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
	proof, err := plonk.Prove(ccs, pkey, witness,
		recursive_plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	fmt.Println("verifying ...")
	err = plonk.Verify(proof, vkey, witness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	proofFile, err := os.Create(chainark.GenesisProofFile)
	if err != nil {
		panic(err)
	}
	proof.WriteTo(proofFile)
	proofFile.Close()
	fmt.Println("saved proof")
}
