package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func AssertIDWitness[FR emulated.FieldParams](api frontend.API, id LinkageID, witnessValues []emulated.Element[FR]) {
	AssertValsVSWtnsElements[FR](api, id.Vals, witnessValues)
}

func AssertFpWitness[FR emulated.FieldParams](api frontend.API, fp FingerPrint, witnessValues []emulated.Element[FR]) {
	AssertValsVSWtnsElements[FR](api, fp.Vals, witnessValues)
}

func AssertValsVSWtnsElements[FR emulated.FieldParams](api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR]) {
	api.AssertIsEqual(len(witnessValues), len(vars))

	var fr FR
	bitsPerLimb := FR.BitsPerLimb(fr)
	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	nbLimbs := len(witnessValues[0].Limbs)
	for i := 0; i < len(vars); i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := frontend.Variable(eleLimbs[nbLimbs-1])
		for j := nbLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		api.AssertIsEqual(vars[i], composed)
	}
}
