package main

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/chainark/example/utils"
)

// TestGenesis_Simulated only can be runned after unit ccs/pk/vk/proof/witness files are generated
func TestGenesis_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	var fps []common_utils.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		fps = append(fps, common_utils.FingerPrintBytes(fp))
	}

	innerCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	circuit := chainark.NewGenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal, innerCcs, fps)

	_innerVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(8)))
	assert.NoError(err)

	innerVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_innerVk)
	assert.NoError(err)
	_innerProof, err := operations.ReadProof(filepath.Join(dataDir, "unit_0_8.proof"))
	assert.NoError(err)

	innerProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_innerProof)
	assert.NoError(err)
	_innerWit, err := operations.ReadWitness(filepath.Join(dataDir, "unit_0_8.wtns"))
	assert.NoError(err)

	innerWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_innerWit)
	assert.NoError(err)

	beginIDBytes, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)
	beginID := chainark.LinkageIDFromBytes(beginIDBytes, common.NbBitsPerIDVal)

	endIDBytes, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)
	endID := chainark.LinkageIDFromBytes(endIDBytes, common.NbBitsPerIDVal)

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recusiveVkFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recusiveVkFp := common_utils.FingerPrintFromBytes(recusiveVkFpBytes, common.NbBitsPerFpVal)

	assignment := chainark.NewGenesisAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		innerVk,
		innerProof,
		innerWit,
		recusiveVkFp,
		beginID,
		endID,
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestGenesis_Plonk_BN254(t *testing.T) {
	assert := test.NewAssert(t)

	var fps []common_utils.FingerPrintBytes
	for i := 3; i >= 0; i-- {
		n := 1 << i
		vk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(n)))
		assert.NoError(err)

		fp, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		fps = append(fps, fp)
	}

	innerCcs, err := operations.ReadCcs(filepath.Join(dataDir, utils.UnitCcsFile(1)))
	assert.NoError(err)

	ccs := NewGenesisCcs(innerCcs, fps)

	_innerVk, err := operations.ReadVk(filepath.Join(dataDir, utils.UnitVkFile(8)))
	assert.NoError(err)

	innerVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_innerVk)
	assert.NoError(err)
	_innerProof, err := operations.ReadProof(filepath.Join(dataDir, "unit_0_8.proof"))
	assert.NoError(err)

	innerProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](_innerProof)
	assert.NoError(err)
	_innerWit, err := operations.ReadWitness(filepath.Join(dataDir, "unit_0_8.wtns"))
	assert.NoError(err)

	innerWit, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](_innerWit)
	assert.NoError(err)

	beginIDBytes, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)
	beginID := chainark.LinkageIDFromBytes(beginIDBytes, common.NbBitsPerIDVal)

	endIDBytes, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)
	endID := chainark.LinkageIDFromBytes(endIDBytes, common.NbBitsPerIDVal)

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)

	recusiveVkFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recusiveVkFp := common_utils.FingerPrintFromBytes(recusiveVkFpBytes, common.NbBitsPerFpVal)

	assignment := chainark.NewGenesisAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		innerVk,
		innerProof,
		innerWit,
		recusiveVkFp,
		beginID,
		endID,
	)

	// let's generate the files again
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	assert.NoError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	pubWitness, err := witness.Public()
	assert.NoError(err)

	proof, err := plonk.Prove(ccs, pk, witness)
	assert.NoError(err)

	err = plonk.Verify(proof, vk, pubWitness)
	assert.NoError(err)

}
