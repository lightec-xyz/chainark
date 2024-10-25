package main

import (
	"encoding/hex"
	"path/filepath"
	"testing"

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

	var unitVkFps []chainark.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		unitVkFps = append(unitVkFps, chainark.FingerPrintBytes(fp))
	}

	genesisVk, err := utils.ReadVk(filepath.Join(dataDir, common.GenesisVkFile))
	assert.NoError(err)

	genesisVkFp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](genesisVk)
	assert.NoError(err)

	recursiveVk, err := utils.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := chainark.FingerPrintFromBytes(recursiveVkFpBytes, common.NbBitsPerFpVal)

	unitCcs, err := utils.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	genesisCcs, err := utils.ReadCcs(filepath.Join(dataDir, common.GenesisCcsFile))
	assert.NoError(err)

	circuit := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, genesisCcs,
		genesisVkFp, unitVkFps,
	)

	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](genesisVk)
	assert.NoError(err)

	_secondVk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(4)))
	assert.NoError(err)

	secondVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondVk)
	assert.NoError(err)

	_firstProof, err := utils.ReadProof(filepath.Join(dataDir, "genesis_0_8.proof"))
	assert.NoError(err)

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	assert.NoError(err)

	_firstWit, err := utils.ReadWitness(filepath.Join(dataDir, "genesis_0_8.wit"))
	assert.NoError(err)

	firstWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWit)
	assert.NoError(err)

	_secondProof, err := utils.ReadProof(filepath.Join(dataDir, "unit_8_12.proof"))
	assert.NoError(err)

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	assert.NoError(err)

	_secondWit, err := utils.ReadWitness(filepath.Join(dataDir, "unit_8_12.wit"))
	assert.NoError(err)

	secondWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_secondWit)
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
		firstWit, secondWit,
		recursiveVkFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
		8, 4, 12,
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestRecursive_0_14_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	var unitVkFps []chainark.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		unitVkFps = append(unitVkFps, chainark.FingerPrintBytes(fp))
	}

	genesisVk, err := utils.ReadVk(filepath.Join(dataDir, common.GenesisVkFile))
	assert.NoError(err)

	genesisVkFp, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](genesisVk)
	assert.NoError(err)

	recursiveVk, err := utils.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := chainark.FingerPrintFromBytes(recursiveVkFpBytes, common.NbBitsPerFpVal)

	unitCcs, err := utils.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	genesisCcs, err := utils.ReadCcs(filepath.Join(dataDir, common.GenesisCcsFile))
	assert.NoError(err)

	circuit := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal,
		unitCcs, genesisCcs,
		genesisVkFp, unitVkFps,
	)

	_firstVk, err := utils.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)
	firstVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstVk)
	assert.NoError(err)

	_secondVk, err := utils.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(2)))
	assert.NoError(err)
	secondVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondVk)
	assert.NoError(err)

	_firstProof, err := utils.ReadProof(filepath.Join(dataDir, "recursive_0_12.proof"))
	assert.NoError(err)

	firstProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_firstProof)
	assert.NoError(err)

	_firstWit, err := utils.ReadWitness(filepath.Join(dataDir, "recursive_0_12.wit"))
	assert.NoError(err)

	firstWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_firstWit)
	assert.NoError(err)

	_secondProof, err := utils.ReadProof(filepath.Join(dataDir, "unit_12_14.proof"))
	assert.NoError(err)

	secondProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_secondProof)
	assert.NoError(err)

	_secondWit, err := utils.ReadWitness(filepath.Join(dataDir, "unit_12_14.wit"))
	assert.NoError(err)

	secondWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_secondWit)
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
		firstWit, secondWit,
		recursiveVkFp,
		chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(relayID, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
		12, 2, 14,
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
