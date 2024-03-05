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
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sha256 "github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
)

const IDLength = 32

type UnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID chainark.LinkageID `gnark:",public"`
	EndID   chainark.LinkageID `gnark:",public"`
}

func (uc *UnitCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	s256, err := sha256.New(api)
	if err != nil {
		return err
	}
	s256.Write(uc.BeginID)
	s256.Write(uints.NewU8Array(([]byte)("chainark example")))

	r := (chainark.LinkageID)(s256.Sum())

	idTest := uc.EndID.IsEqual(api, &r)
	api.AssertIsEqual(idTest, 1)

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./example --setup")
		fmt.Println("usage: ./example beginIdHex endIdHex")
		return
	}

	// log := logger.Logger()

	var circuit UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	// note that we need to supply the actual length to the circuit, so mock some data just for the sake of circuit definition
	circuit.BeginID = make([]uints.U8, 32)
	circuit.EndID = make([]uints.U8, 32)

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

		pkFile, err := os.Create("pkey")
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		vkFile, err := os.Create("vkey")
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		fmt.Println("saved pkey and vkey")
		return
	}

	if len(os.Args) < 3 || len(os.Args[1]) != 64 || len(os.Args[2]) != 64 {
		fmt.Println("usage: ./example beginIdHex endIdHex\nNote that the Id is some value of SHA256, thus 32 bytes.")
		return
	}

	beginHex := os.Args[1]
	beginBytes := make([]byte, len(beginHex)/2)
	endHex := os.Args[2]
	endBytes := make([]byte, len(endHex)/2)
	hex.Decode(beginBytes, []byte(beginHex))
	hex.Decode(endBytes, []byte(endHex))

	var w UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	w.BeginID = uints.NewU8Array(beginBytes)
	w.EndID = uints.NewU8Array(endBytes)
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	fmt.Println("loading keys ...")
	pkey := plonk.NewProvingKey(ecc.BN254)
	vkey := plonk.NewVerifyingKey(ecc.BN254)

	pkFile, err := os.Open("pkey")
	if err != nil {
		panic(err)
	}
	pkey.ReadFrom(pkFile)
	pkFile.Close()

	vkFile, err := os.Open("vkey")
	if err != nil {
		panic(err)
	}
	vkey.ReadFrom(vkFile)
	vkFile.Close()

	fmt.Println("proving ...")
	proof, err := plonk.Prove(ccs, pkey, witness)
	if err != nil {
		panic(err)
	}

	fmt.Println("verifying ...")
	err = plonk.Verify(proof, vkey, witness)
	if err != nil {
		panic(err)
	}

	proofFile, err := os.Create("proof")
	if err != nil {
		panic(err)
	}
	proof.WriteTo(proofFile)
	proofFile.Close()
	fmt.Println("saved proof")
}
