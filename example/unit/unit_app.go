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
		fmt.Println("usage: ./unit --setup")
		fmt.Println("usage: ./unit beginIdHex endIdHex")
		return
	}

	circuit := chainark.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: make([]uints.U8, chainark.IDLength),
		EndID:   make([]uints.U8, chainark.IDLength),
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

		pkFile, err := os.Create(chainark.UnitPkeyFile)
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		vkFile, err := os.Create(chainark.UnitVkeyFile)
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		fmt.Println("saved pkey and vkey")
		return
	}

	if len(os.Args) < 3 || len(os.Args[1]) != chainark.IDLength*2 || len(os.Args[2]) != chainark.IDLength*2 {
		fmt.Println("usage: ./unit beginIdHex endIdHex\nNote that the Id is some value of SHA256, thus 32 bytes.")
		return
	}

	beginHex := os.Args[1]
	beginBytes := make([]byte, len(beginHex)/2)
	endHex := os.Args[2]
	endBytes := make([]byte, len(endHex)/2)
	hex.Decode(beginBytes, []byte(beginHex))
	hex.Decode(endBytes, []byte(endHex))

	w := chainark.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: uints.NewU8Array(beginBytes),
		EndID:   uints.NewU8Array(endBytes),
	}
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	fmt.Println("loading keys ...")
	pkey := plonk.NewProvingKey(ecc.BN254)
	vkey := plonk.NewVerifyingKey(ecc.BN254)

	pkFile, err := os.Open(chainark.UnitPkeyFile)
	if err != nil {
		panic(err)
	}
	pkey.ReadFrom(pkFile)
	pkFile.Close()

	vkFile, err := os.Open(chainark.UnitVkeyFile)
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
	err = plonk.Verify(proof, vkey, witness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	proofFile, err := os.Create(chainark.UnitProofFile)
	if err != nil {
		panic(err)
	}
	proof.WriteTo(proofFile)
	proofFile.Close()
	fmt.Println("saved proof")
}
