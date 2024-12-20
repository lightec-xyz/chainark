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
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/utils"
	"github.com/lightec-xyz/common/operations"
	common_utils "github.com/lightec-xyz/common/utils"
)

var dataDir = "../testdata"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./genesis setup")
		fmt.Println("usage: ./genesis prove beginID endID beginIndex endIndex")
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
		fmt.Println("usage: ./genesis setup")
		fmt.Println("usage: ./genesis prove beginID endID beginIndex endIndex")
		return
	}
}

func setup() {
	var fps []common_utils.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		if err != nil {
			panic(err)
		}

		fp, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		if err != nil {
			panic(err)
		}
		fps = append(fps, common_utils.FingerPrintBytes(fp))
	}

	innerCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	if err != nil {
		panic(err)
	}

	ccs := NewGenesisCcs(innerCcs, fps)
	// let's generate the files again
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	err = operations.WriteCcs(ccs, filepath.Join(dataDir, common.GenesisCcsFile))
	if err != nil {
		panic(err)
	}

	err = operations.WritePk(pk, filepath.Join(dataDir, common.GenesisPkFile))
	if err != nil {
		panic(err)
	}

	err = operations.WriteVk(vk, filepath.Join(dataDir, common.GenesisVkFile))
	if err != nil {
		panic(err)
	}
	fmt.Println("saved genesis ccs, pk, vk")
}

func prove(args []string) {
	if len(args) != 4 {
		panic("expected 4 parameters")
	}

	beginIndex, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		panic(err)
	}

	endIndex, err := strconv.ParseInt(args[3], 10, 32)
	if err != nil {
		panic(err)
	}
	nbIDs := int(endIndex - beginIndex)

	//load proof
	_innerProof, err := operations.ReadProof(filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.proof", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}
	innerProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_innerProof)
	if err != nil {
		panic(err)
	}

	//load public witness
	_innerWitness, err := operations.ReadWitness(filepath.Join(dataDir, fmt.Sprintf("unit_%v_%v.wtns", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	innerWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_innerWitness)
	if err != nil {
		panic(err)
	}

	//load beginID and endID
	l := common.NbIDVals * common.NbBitsPerIDVal * 2 / 8
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

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	recursiveFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	if err != nil {
		panic(err)
	}
	recursiveFp := common_utils.FingerPrintFromBytes(recursiveFpBytes, common.NbBitsPerFpVal)

	_unitVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(nbIDs)))
	if err != nil {
		panic(err)
	}

	unitVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_unitVk)
	if err != nil {
		panic(err)
	}

	//build assignment
	assignment := chainark.NewGenesisAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitVk,
		innerProof,
		innerWitness,
		recursiveFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
	)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	fmt.Println("loading ccs, pk, vk ...")

	ccs, err := operations.ReadCcs(filepath.Join(dataDir, common.GenesisCcsFile))
	if err != nil {
		panic(err)
	}

	pk, err := operations.ReadPk(filepath.Join(dataDir, common.GenesisPkFile))
	if err != nil {
		panic(err)
	}

	vk, err := operations.ReadVk(filepath.Join(dataDir, common.GenesisVkFile))
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
	err = operations.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("genesis_%v_%v.proof", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = operations.WriteWitness(pubWitness, filepath.Join(dataDir, fmt.Sprintf("genesis_%v_%v.wtns", beginIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}

func NewGenesisCcs(
	unitCcs constraint.ConstraintSystem,
	unitFps []common_utils.FingerPrintBytes,
) constraint.ConstraintSystem {
	circuit := chainark.NewGenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, unitFps)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}

	return ccs
}
