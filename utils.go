package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
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
