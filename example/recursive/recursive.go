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
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/unit/core"
	"github.com/lightec-xyz/chainark/example/utils"
	"github.com/lightec-xyz/common/operations"
	common_utils "github.com/lightec-xyz/common/utils"
)

var dataDir = "../testdata"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./recursive setup [optimization]")
		fmt.Println("usage: ./recursive prove firstProof firstWitness secondProof secondWitness beginID relayID endID beginIndex endIndex")
		fmt.Println("usage: ./recursive provehybrid firstProof firstWitness beginID relayID endID beginIndex endIndex")
		return
	}

	flag.NewFlagSet("setup", flag.ExitOnError)
	flag.NewFlagSet("prove", flag.ExitOnError)
	flag.NewFlagSet("provehybrid", flag.ExitOnError)

	switch os.Args[1] {
	case "setup":
		{
			opt := false
			var err error
			if len(os.Args) >= 3 {
				opt, err = strconv.ParseBool(os.Args[2])
				if err != nil {
					fmt.Printf("optimization must be bool: %s\n", os.Args[2])
					return
				}
			}

			setup(opt)
		}
	case "prove":
		prove(os.Args[2:])
	case "provehybrid":
		hybrid(os.Args[2:])
	default:
		fmt.Println("usage: ./recursive setup [optimization]")
		fmt.Println("usage: ./recursive prove firstVkFile firstProofFile firstWitFile secondProofFile secondWitFile beginID relayID endID beginIndex relayIndex endIndex")
		fmt.Println("usage: ./recursive provehybrid firstProof firstWitness beginID relayID endID beginIndex endIndex")
		return
	}
}

func setup(opt bool) {
	var unitVkFps []common_utils.FingerPrintBytes
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
		unitVkFps = append(unitVkFps, common_utils.FingerPrintBytes(fp))
	}

	unitCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	if err != nil {
		panic(err)
	}

	recursiveCircuit := chainark.NewMultiRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, unitVkFps, 2, opt)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, recursiveCircuit)
	if err != nil {
		panic(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	err = operations.WriteCcs(ccs, filepath.Join(dataDir, common.RecursiveCcsFile))
	if err != nil {
		panic(err)
	}

	err = operations.WritePk(pk, filepath.Join(dataDir, common.RecursivePkFile))
	if err != nil {
		panic(err)
	}

	err = operations.WriteVk(vk, filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	fmt.Println("saved recursive ccs, pk, vk")

	iter := core.NewIteratedHashCircuit(4) // just an example, not meant to be full
	hybridCircuit := chainark.NewHybridCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, unitVkFps, 2, iter)
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, hybridCircuit)
	if err != nil {
		panic(err)
	}

	srs, srsLagrange, err = unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, vk, err = plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	err = operations.WriteCcs(ccs, filepath.Join(dataDir, common.HybridCcsFile))
	if err != nil {
		panic(err)
	}

	err = operations.WritePk(pk, filepath.Join(dataDir, common.HybridPkFile))
	if err != nil {
		panic(err)
	}

	err = operations.WriteVk(vk, filepath.Join(dataDir, common.HybridVkFile))
	if err != nil {
		panic(err)
	}
	fmt.Println("saved hybrid ccs, pk, vk")
}

func prove(args []string) {
	l := common.NbIDVals * common.NbBitsPerIDVal * 2 / 8
	if len(args) != 11 {
		panic("expected 11 parameters")
	}

	//load first vk
	_firstVk, err := operations.ReadVk(filepath.Join(dataDir, args[0]))
	if err != nil {
		panic(err)
	}

	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstVk)
	if err != nil {
		panic(err)
	}

	//load first proof&witness
	_firstProof, err := operations.ReadProof(filepath.Join(dataDir, args[1]))
	if err != nil {
		panic(err)
	}

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	if err != nil {
		panic(err)
	}

	_firstWitness, err := operations.ReadWitness(filepath.Join(dataDir, args[2]))
	if err != nil {
		panic(err)
	}

	firstWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWitness)
	if err != nil {
		panic(err)
	}

	//load second proof&witness
	_secondProof, err := operations.ReadProof(filepath.Join(dataDir, args[3]))
	if err != nil {
		panic(err)
	}

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	if err != nil {
		panic(err)
	}

	_secondWitness, err := operations.ReadWitness(filepath.Join(dataDir, args[4]))
	if err != nil {
		panic(err)
	}
	secondWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_secondWitness)
	if err != nil {
		panic(err)
	}

	beginHex := args[5]
	relayHex := args[6]
	endHex := args[7]

	if len(beginHex) != l || len(relayHex) != l || len(endHex) != l {
		panic("expected 32 bytes")
	}

	beginID, err := hex.DecodeString(beginHex)
	if err != nil {
		panic(err)
	}

	relayID, err := hex.DecodeString(relayHex)
	if err != nil {
		panic(err)
	}

	endID, err := hex.DecodeString(endHex)
	if err != nil {
		panic(err)
	}

	beignIndex, err := strconv.ParseInt(args[8], 10, 32)
	if err != nil {
		panic(err)
	}

	relayIndex, err := strconv.ParseInt(args[9], 10, 32)
	if err != nil {
		panic(err)
	}

	endIndex, err := strconv.ParseInt(args[10], 10, 32)
	if err != nil {
		panic(err)
	}

	nbIDsInFirstWit := int(relayIndex - beignIndex)
	nbIDsInSecondWit := int(endIndex - relayIndex)
	nbIDs := nbIDsInFirstWit + nbIDsInSecondWit
	println("total ids in the proof", nbIDs)

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	recursiveFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	if err != nil {
		panic(err)
	}
	recursiveFp := common_utils.FingerPrintFromBytes(recursiveFpBytes, common.NbBitsPerFpVal)

	hybridVk, err := operations.ReadVk(filepath.Join(dataDir, common.HybridVkFile))
	if err != nil {
		panic(err)
	}
	hybridFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hybridVk)
	if err != nil {
		panic(err)
	}
	hybridFp := common_utils.FingerPrintFromBytes(hybridFpBytes, common.NbBitsPerFpVal)

	_unitVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(nbIDsInSecondWit)))
	if err != nil {
		panic(err)
	}

	unitVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_unitVk)
	if err != nil {
		panic(err)
	}

	assignment := chainark.NewMultiRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		firstVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		[]common_utils.FingerPrint{recursiveFp, hybridFp},
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
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
	ccs, err := operations.ReadCcs(filepath.Join(dataDir, common.RecursiveCcsFile))
	if err != nil {
		panic(err)
	}

	pk, err := operations.ReadPk(filepath.Join(dataDir, common.RecursivePkFile))
	if err != nil {
		panic(err)
	}

	vk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
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
	err = operations.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.proof", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = operations.WriteWitness(pubWitness, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.wtns", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}

func hybrid(args []string) {
	l := common.NbIDVals * common.NbBitsPerIDVal * 2 / 8
	if len(args) != 9 {
		panic("expected 9 parameters")
	}

	//load first vk
	_firstVk, err := operations.ReadVk(filepath.Join(dataDir, args[0]))
	if err != nil {
		panic(err)
	}

	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstVk)
	if err != nil {
		panic(err)
	}

	//load first proof&witness
	_firstProof, err := operations.ReadProof(filepath.Join(dataDir, args[1]))
	if err != nil {
		panic(err)
	}

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	if err != nil {
		panic(err)
	}

	_firstWitness, err := operations.ReadWitness(filepath.Join(dataDir, args[2]))
	if err != nil {
		panic(err)
	}

	firstWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWitness)
	if err != nil {
		panic(err)
	}

	beginHex := args[3]
	relayHex := args[4]
	endHex := args[5]

	if len(beginHex) != l || len(relayHex) != l || len(endHex) != l {
		panic("expected 32 bytes")
	}

	beginID, err := hex.DecodeString(beginHex)
	if err != nil {
		panic(err)
	}

	relayID, err := hex.DecodeString(relayHex)
	if err != nil {
		panic(err)
	}

	endID, err := hex.DecodeString(endHex)
	if err != nil {
		panic(err)
	}

	beignIndex, err := strconv.ParseInt(args[6], 10, 32)
	if err != nil {
		panic(err)
	}

	relayIndex, err := strconv.ParseInt(args[7], 10, 32)
	if err != nil {
		panic(err)
	}

	endIndex, err := strconv.ParseInt(args[8], 10, 32)
	if err != nil {
		panic(err)
	}

	nbIDsInFirstWit := int(relayIndex - beignIndex)
	nbIDsInSecondWit := int(endIndex - relayIndex)
	nbIDs := nbIDsInFirstWit + nbIDsInSecondWit
	println("total ids in the proof", nbIDs)

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	recursiveFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	if err != nil {
		panic(err)
	}
	recursiveFp := common_utils.FingerPrintFromBytes(recursiveFpBytes, common.NbBitsPerFpVal)

	hybridVk, err := operations.ReadVk(filepath.Join(dataDir, common.HybridVkFile))
	if err != nil {
		panic(err)
	}
	hybridFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hybridVk)
	if err != nil {
		panic(err)
	}
	hybridFp := common_utils.FingerPrintFromBytes(hybridFpBytes, common.NbBitsPerFpVal)

	iter := core.NewIteratedHashAssignement(relayID, endID)
	assignment := chainark.NewHybridAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		firstVk,
		firstProof,
		firstWitness,
		[]common_utils.FingerPrint{recursiveFp, hybridFp},
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
		iter,
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
	ccs, err := operations.ReadCcs(filepath.Join(dataDir, common.HybridCcsFile))
	if err != nil {
		panic(err)
	}

	pk, err := operations.ReadPk(filepath.Join(dataDir, common.HybridPkFile))
	if err != nil {
		panic(err)
	}

	vk, err := operations.ReadVk(filepath.Join(dataDir, common.HybridVkFile))
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
	err = operations.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.proof", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = operations.WriteWitness(pubWitness, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.wtns", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}
