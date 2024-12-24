package chainark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type idTestCircuit struct {
	Eles     [2]emulated.Element[sw_bn254.ScalarField]
	Id       LinkageID
	Expected frontend.Variable
}

func (c *idTestCircuit) Define(api frontend.API) error {
	t := TestIDWitness[sw_bn254.ScalarField](api, c.Id, c.Eles[:], 128)
	api.AssertIsEqual(t, c.Expected)

	return nil
}

func TestIdVSWitness(t *testing.T) {
	limbs1 := [4]uint64{0x012345, 0x6789ab, 0, 0}
	limbs2 := [4]uint64{0xaa, 0xbb, 0, 0}
	ele1 := emulated.Element[sw_bn254.ScalarField]{
		Limbs: []frontend.Variable{
			frontend.Variable(limbs1[0]),
			frontend.Variable(limbs1[1]),
			frontend.Variable(limbs1[2]),
			frontend.Variable(limbs1[3]),
		},
	}
	ele2 := emulated.Element[sw_bn254.ScalarField]{
		Limbs: []frontend.Variable{
			frontend.Variable(limbs2[0]),
			frontend.Variable(limbs2[1]),
			frontend.Variable(limbs2[2]),
			frontend.Variable(limbs2[3]),
		},
	}
	eles := [2]emulated.Element[sw_bn254.ScalarField]{ele1, ele2}

	bi1, ok := big.NewInt(0).SetString("6789ab0000000000012345", 16)
	if !ok {
		panic("bi1")
	}
	bi2, ok := big.NewInt(0).SetString("bb00000000000000aa", 16)
	if !ok {
		panic("bi2")
	}
	id := LinkageID{Vals: []frontend.Variable{frontend.Variable(bi1), frontend.Variable(bi2)}, BitsPerVar: 128}

	circuit := &idTestCircuit{
		Id: PlaceholderLinkageID(2, 128),
	}
	assignment := &idTestCircuit{
		Eles:     eles,
		Id:       id,
		Expected: 1,
	}
	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)

	eles[0].Limbs[1] = frontend.Variable(100)
	assignment2 := &idTestCircuit{
		Eles:     eles,
		Id:       id,
		Expected: 0,
	}
	err = test.IsSolved(circuit, assignment2, ecc.BN254.ScalarField())
	assert.NoError(err)
}
