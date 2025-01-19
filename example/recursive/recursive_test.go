package main

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/lightec-xyz/common/operations"
	common_utils "github.com/lightec-xyz/common/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/utils"
)

func TestRecursive_0_12_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	var unitVkFps []common_utils.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		unitVkFps = append(unitVkFps, common_utils.FingerPrintBytes(fp))
	}

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recursiveVkFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := common_utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	unitCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	circuit := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal,
		unitCcs, unitVkFps,
	)

	_fristVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(8)))
	assert.NoError(err)

	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_fristVk)
	assert.NoError(err)

	_secondVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(4)))
	assert.NoError(err)

	secondVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondVk)
	assert.NoError(err)

	_firstProof, err := operations.ReadProof(filepath.Join(dataDir, "unit_0_8.proof"))
	assert.NoError(err)

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	assert.NoError(err)

	_firstWitness, err := operations.ReadWitness(filepath.Join(dataDir, "unit_0_8.wtns"))
	assert.NoError(err)

	firstWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWitness)
	assert.NoError(err)

	_secondProof, err := operations.ReadProof(filepath.Join(dataDir, "unit_8_12.proof"))
	assert.NoError(err)

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	assert.NoError(err)

	_secondWitness, err := operations.ReadWitness(filepath.Join(dataDir, "unit_8_12.wtns"))
	assert.NoError(err)

	secondWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_secondWitness)
	assert.NoError(err)

	beginID, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)

	relayID, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)

	endID, err := hex.DecodeString("016f736042472bd002d5620f0032f37e79779ffcc56eee785e4833edee2c9176")
	assert.NoError(err)

	assignment := chainark.NewRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		firstVk, secondVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestRecursive_0_14_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	var unitVkFps []common_utils.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		unitVkFps = append(unitVkFps, common_utils.FingerPrintBytes(fp))
	}

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recursiveVkFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := common_utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	unitCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	circuit := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal,
		unitCcs, unitVkFps,
	)

	_firstVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)
	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstVk)
	assert.NoError(err)

	_secondVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(2)))
	assert.NoError(err)
	secondVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondVk)
	assert.NoError(err)

	_firstProof, err := operations.ReadProof(filepath.Join(dataDir, "recursive_0_12.proof"))
	assert.NoError(err)

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	assert.NoError(err)

	_firstWitness, err := operations.ReadWitness(filepath.Join(dataDir, "recursive_0_12.wtns"))
	assert.NoError(err)

	firstWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWitness)
	assert.NoError(err)

	_secondProof, err := operations.ReadProof(filepath.Join(dataDir, "unit_12_14.proof"))
	assert.NoError(err)

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	assert.NoError(err)

	_secondWitness, err := operations.ReadWitness(filepath.Join(dataDir, "unit_12_14.wtns"))
	assert.NoError(err)

	secondWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_secondWitness)
	assert.NoError(err)

	beginID, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)

	relayID, err := hex.DecodeString("016f736042472bd002d5620f0032f37e79779ffcc56eee785e4833edee2c9176")
	assert.NoError(err)

	endID, err := hex.DecodeString("2741ec6c2ad44e316d513e8b838ad20a7262aeeac02299e5d817c60c4399f0b4")
	assert.NoError(err)

	assignment := chainark.NewRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		firstVk, secondVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
