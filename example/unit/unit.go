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
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/unit/core"
	"github.com/lightec-xyz/chainark/example/utils"
	"github.com/lightec-xyz/common/operations"
)

var dataDir = "../testdata"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./unit setup [extra]")
		fmt.Println("usage: ./unit prove beginIdHex endIdHex beginIndex endIndex")
		return
	}

	flag.NewFlagSet("setup", flag.ExitOnError)
	flag.NewFlagSet("prove", flag.ExitOnError)

	switch os.Args[1] {
	case "setup":
		{
			extra := 0
			var err error
			if len(os.Args) >= 3 {
				extra, err = strconv.Atoi(os.Args[2])
				if err != nil {
					fmt.Errorf("extra must be integer")
					return
				}
			}
			setup(extra)
		}
	case "prove":
		prove(os.Args[2:])
	default:
		fmt.Println("usage: ./unit setup [extra]")
		fmt.Println("usage: ./unit prove beginIdHex endIdHex beginIndex endIndex")
		return
	}
}

func NewUnitCcs(n, extra int) constraint.ConstraintSystem {
	unit := core.NewUnitCircuit(n, extra)
	unitCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, unit)
	if err != nil {
		panic(err)
	}
	return unitCcs
}

func setup(extra int) {
	for i := 3; i >= 0; i-- {
		n := 1 << i
		fmt.Printf("setting up for n = %v\n", n)

		ccs := NewUnitCcs(n, extra)

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

	assignment := core.NewUnitAssignement(beginID, endID)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	fmt.Println("loading ccs, pk, vk ...")
	ccs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(nbIter)))
	if err != nil {
		panic(err)
	}

	pk, err := operations.ReadPk(filepath.Join(dataDir, utils.UnitPkFile(nbIter)))
	if err != nil {
		panic(err)
	}

	vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(nbIter)))
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
	err = plonk.Verify(proof, vk, pubWitness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		panic(err)
	}

	fmt.Println("saving proof and witness ...")
	err = operations.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.proof", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = operations.WriteWitness(pubWitness, filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.wtns", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}
