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
)

var dataDir = "../testdata"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./recursive setup")
		fmt.Println("usage: ./recursive prove firstProof firstWitness secondProof secondWitness beginID relayID endID beginIndex endIndex")
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
		fmt.Println("usage: ./recursive setup")
		fmt.Println("usage: ./recursive prove firstVkFile firstProofFile firstWitFile secondProofFile secondWitFile beginID relayID endID beginIndex relayIndex endIndex")
		return
	}
}

func setup() {
	var unitVkFps []chainark.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		if err != nil {
			panic(err)
		}

		fp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		if err != nil {
			panic(err)
		}
		unitVkFps = append(unitVkFps, chainark.FingerPrintBytes(fp))
	}

	vk, err := utils.ReadVk(filepath.Join(dataDir, common.GenesisVkFile))
	if err != nil {
		panic(err)
	}

	genesisVkFp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	if err != nil {
		panic(err)
	}

	unitCcs, err := utils.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	if err != nil {
		panic(err)
	}

	genesisCcs, err := utils.ReadCcs(filepath.Join(dataDir, common.GenesisCcsFile))
	if err != nil {
		panic(err)
	}

	ccs := NewRecursiveCcs(unitCcs, genesisCcs, genesisVkFp, unitVkFps)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	err = utils.WriteCcs(ccs, filepath.Join(dataDir, common.RecursiveCcsFile))
	if err != nil {
		panic(err)
	}

	err = utils.WritePk(pk, filepath.Join(dataDir, common.RecursivePkFile))
	if err != nil {
		panic(err)
	}

	err = utils.WriteVk(vk, filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	fmt.Println("saved genesis ccs, pk, vk")
}

func prove(args []string) {
	l := common.NbIDVals * common.NbBitsPerIDVal * 2 / 8
	if len(args) != 11 {
		panic("expected 11 parameters")
	}

	//load first vk
	_firstVk, err := utils.ReadVk(filepath.Join(dataDir, args[0]))
	if err != nil {
		panic(err)
	}

	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstVk)
	if err != nil {
		panic(err)
	}

	//load first proof&witness
	_firstProof, err := utils.ReadProof(filepath.Join(dataDir, args[1]))
	if err != nil {
		panic(err)
	}

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	if err != nil {
		panic(err)
	}

	_firstWitness, err := utils.ReadWitness(filepath.Join(dataDir, args[2]))
	if err != nil {
		panic(err)
	}

	firstWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWitness)
	if err != nil {
		panic(err)
	}

	//load second proof&witness
	_secondProof, err := utils.ReadProof(filepath.Join(dataDir, args[3]))
	if err != nil {
		panic(err)
	}

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	if err != nil {
		panic(err)
	}

	_secondWitness, err := utils.ReadWitness(filepath.Join(dataDir, args[4]))
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

	recursiveVk, err := utils.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	if err != nil {
		panic(err)
	}
	recursiveFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	if err != nil {
		panic(err)
	}
	recursiveFp := chainark.FingerPrintFromBytes(recursiveFpBytes, common.NbBitsPerFpVal)

	_unitVk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(nbIDsInSecondWit)))
	if err != nil {
		panic(err)
	}

	unitVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_unitVk)
	if err != nil {
		panic(err)
	}

	assignment := chainark.NewRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		firstVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
		nbIDsInFirstWit, nbIDsInSecondWit, nbIDs,
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
	ccs, err := utils.ReadCcs(filepath.Join(dataDir, common.RecursiveCcsFile))
	if err != nil {
		panic(err)
	}

	pk, err := utils.ReadPk(filepath.Join(dataDir, common.RecursivePkFile))
	if err != nil {
		panic(err)
	}

	vk, err := utils.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
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
	err = utils.WriteProof(proof, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.proof", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}

	err = utils.WriteWitness(pubWitness, filepath.Join(dataDir, fmt.Sprintf("recursive_%v_%v.wtns", beignIndex, endIndex)))
	if err != nil {
		panic(err)
	}
}

func NewRecursiveCcs(
	unitCcs constraint.ConstraintSystem,
	genesisCcs constraint.ConstraintSystem,
	genesisVkFp chainark.FingerPrintBytes,
	unitVkFps []chainark.FingerPrintBytes,
) constraint.ConstraintSystem {
	recursive := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, genesisCcs, genesisVkFp, unitVkFps)
	recursiveCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, recursive)
	if err != nil {
		panic(err)
	}
	return recursiveCcs
}
