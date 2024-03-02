package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
)

func createWitness[FR emulated.FieldParams](assignment frontend.Circuit, field *big.Int) (*plonk.Witness[FR], error) {
	w, err := frontend.NewWitness(assignment, field, frontend.PublicOnly())
	if err != nil {
		return nil, err
	}

	witness, err := plonk.ValueOfWitness[FR](w)
	if err != nil {
		return nil, err
	}

	return &witness, nil
}

func testU8ArrayEquality(api frontend.API, a, b []uints.U8) frontend.Variable {
	len1 := len(a)
	len2 := len(b)
	api.AssertIsEqual(len1, len2) // TODO correctness/forking review

	sum := frontend.Variable(0)
	for i := 0; i < len1; i++ {
		cmp := api.Cmp(a[i].Val, b[i].Val)
		test := api.IsZero(cmp)
		sum = api.Or(sum, test)
	}

	return api.IsZero(sum)
}
