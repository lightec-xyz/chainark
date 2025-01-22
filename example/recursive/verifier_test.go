package main

import (
	"encoding/hex"
	"log"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"
	"github.com/lightec-xyz/common/operations"
	common_utils "github.com/lightec-xyz/common/utils"
)

func Test_Circuit(t *testing.T) {
	assert := test.NewAssert(t)

	recursiveVk, err := operations.ReadVk(filepath.Join(dataDir, common.RecursiveVkFile))
	assert.NoError(err)
	recursiveFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)
	hybridVk, err := operations.ReadVk(filepath.Join(dataDir, common.HybridVkFile))
	assert.NoError(err)
	hybridFpBytes, err := common_utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hybridVk)
	assert.NoError(err)
	hybridCcs, err := operations.ReadCcs(filepath.Join(dataDir, common.RecursiveCcsFile))
	assert.NoError(err)

	circuit, err := NewRecursiveVerifierCircuit(
		hybridCcs,
		[]common_utils.FingerPrintBytes{recursiveFpBytes, hybridFpBytes},
		2, 1, 2,
	)
	assert.NoError(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	log.Printf("nbConstraints: %v, nbSecret: %v, nbPublic: %v",
		cs.GetNbConstraints(), cs.GetNbSecretVariables(), cs.GetNbPublicVariables())

	proof, err := operations.ReadProofAndWitness(
		filepath.Join(dataDir, "recursive_0_23.proof"),
		filepath.Join(dataDir, "recursive_0_23.wtns"),
	)
	assert.NoError(err)

	beginId, _ := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	endId, _ := hex.DecodeString("ad057c8b077361d9f5673d5faa0bf4f6c5013bb5fb745339042329976637a705")
	assignment, err := NewRecursiveVerifierAssignment(
		chainark.LinkageIDFromBytes(beginId, common.NbBitsPerIDVal),
		chainark.LinkageIDFromBytes(endId, common.NbBitsPerIDVal),
		recursiveVk, proof.Proof, proof.Witness,
	)
	assert.NoError(err)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

}
