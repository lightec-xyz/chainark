package core

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

func TestUnitCircuit_8_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	n := 8
	circuit := NewUnitCircuit(n)
	beginID, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)
	endID, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)

	assignment := NewUnitCircuitAssignement(beginID, endID, n)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
func TestUnitCircuit_8_Plonk_BN254(t *testing.T) {
	assert := test.NewAssert(t)

	n := 8
	circuit := NewUnitCircuit(n)
	beginID, err := hex.DecodeString("843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85")
	assert.NoError(err)
	endID, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)

	assignment := NewUnitCircuitAssignement(beginID, endID, n)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}

	// let's generate the files again
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	assert.NoError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	assert.NoError(err)

	pubWit, err := wit.Public()
	assert.NoError(err)

	proof, err := plonk.Prove(ccs, pk, wit)
	assert.NoError(err)

	err = plonk.Verify(proof, vk, pubWit)
	assert.NoError(err)
}

func TestUnitCircuit_4_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	n := 4
	circuit := NewUnitCircuit(n)
	beginID, err := hex.DecodeString("6bb396a01d83bfa27c7476005eacb6dfd2384fc70a016ce2ee145a28288c234c")
	assert.NoError(err)
	endID, err := hex.DecodeString("016f736042472bd002d5620f0032f37e79779ffcc56eee785e4833edee2c9176")
	assert.NoError(err)

	assignment := NewUnitCircuitAssignement(beginID, endID, n)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestUnitCircuit_2_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	n := 2
	circuit := NewUnitCircuit(n)
	beginID, err := hex.DecodeString("016f736042472bd002d5620f0032f37e79779ffcc56eee785e4833edee2c9176")
	assert.NoError(err)
	endID, err := hex.DecodeString("2741ec6c2ad44e316d513e8b838ad20a7262aeeac02299e5d817c60c4399f0b4")
	assert.NoError(err)

	assignment := NewUnitCircuitAssignement(beginID, endID, n)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestUnitCircuit_1_Simulated(t *testing.T) {
	assert := test.NewAssert(t)

	n := 1
	circuit := NewUnitCircuit(n)
	beginID, err := hex.DecodeString("2741ec6c2ad44e316d513e8b838ad20a7262aeeac02299e5d817c60c4399f0b4")
	assert.NoError(err)
	endID, err := hex.DecodeString("65c0875f28da7797071a7870c2b63e84caa028f876674b17f9f25d7c76778634")
	assert.NoError(err)

	assignment := NewUnitCircuitAssignement(beginID, endID, n)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
