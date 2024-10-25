package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/unit/core"
	"github.com/lightec-xyz/chainark/example/utils"
)

var dataDir = "../testdata"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./unit setup")
		fmt.Println("usage: ./unit prove beginIdHex endIdHex beginIndex endIndex")
		return
	}

	flag.NewFlagSet("setup", flag.ExitOnError)
	flag.NewFlagSet("prove", flag.ExitOnError)

	switch os.Args[1] {
	case "setup":
		setup()
	case "prove":
		prove(os.Args[2:])
	default:
		fmt.Println("usage: ./unit setup")
		fmt.Println("usage: ./unit prove beginIdHex endIdHex beginIndex endIndex")
		return
	}
}

func setup() {
	for i := 3; i >= 0; i-- {
		n := 1 << i
		fmt.Printf("setting up for n = %v\n", n)

		ccs := core.NewUnitCcs(n)

		// let's generate the files again
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
		if err != nil {
			panic(err)
		}
		pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
		if err != nil {
			panic(err)
		}

		pkFile, err := os.Create(filepath.Join(dataDir, utils.UnitPkFile(n)))
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		defer pkFile.Close()

		vkFile, err := os.Create(filepath.Join(dataDir, utils.UnitVkFile(n)))
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		defer vkFile.Close()

		ccsFile, err := os.Create(filepath.Join(dataDir, utils.UnitCcsFile(n)))
		if err != nil {
			panic(err)
		}
		ccs.WriteTo(ccsFile)
		defer ccsFile.Close()

		fmt.Println("saved ccs, pk, vk")
	}
}

func prove(args []string) {
	l := common.NbIDVals * common.NbBitsPerIDVal * 2 / 8

	if len(args) != 4 {
		panic("expected 4 parameters")
	}

	beginHex := args[0]
	endHex := args[1]

	if len(beginHex) != l || len(endHex) != l {
		panic("expected 32 bytes")
	}

	beginID, err := hex.DecodeString(beginHex)
	if err != nil {
		panic(err)
	}

	endID, err := hex.DecodeString(endHex)
	if err != nil {
		panic(err)
	}

	beginIndex, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		panic(err)
	}

	endIndex, err := strconv.ParseInt(args[3], 10, 32)
	if err != nil {
		panic(err)
	}

	nbIter := int(endIndex - beginIndex)

	if nbIter != 1 && nbIter != 2 && nbIter != 4 && nbIter != 8 {
		panic("currently, only expected 1, 2, 4, 8")
	}

	assignment := core.NewUnitCircuitAssignement(beginID, endID, nbIter)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}
	pubWit, err := witness.Public()
	if err != nil {
		panic(err)
	}

	fmt.Println("loading ccs, pk, vk ...")
	ccs, err := utils.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(nbIter)))
	if err != nil {
		panic(err)
	}

	pk, err := utils.ReadPk(filepath.Join(dataDir, utils.UnitPkFile(nbIter)))
	if err != nil {
		panic(err)
	}

	vk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(nbIter)))
	if err != nil {
		panic(err)
	}

	fmt.Println("proving ...")
	proof, err := plonk.Prove(ccs, pk, witness,
		recursive_plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	fmt.Println("verifying ...")
	err = plonk.Verify(proof, vk, pubWit,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	fmt.Println("saving proof and witness ...")
	err = utils.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.proof", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = utils.WriteWitness(pubWit, filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.wit", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}
