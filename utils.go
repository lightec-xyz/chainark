package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func AssertIDWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	AssertValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}

func AssertFpWitness[FR emulated.FieldParams](
	api frontend.API, fp FingerPrint, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	AssertValsVSWtnsElements[FR](api, fp.Vals, witnessValues, nbMaxBitsPerVar...)
}

func AssertValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	api.AssertIsEqual(len(witnessValues), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = int(fr.NbLimbs() * fr.BitsPerLimb())
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(witnessValues); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	for i := 0; i < len(vars); i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		api.AssertIsEqual(vars[i], composed)
	}
}

func IsIDEqualToWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	return TestValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}

func TestValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	api.AssertIsEqual(len(witnessValues), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = int(fr.NbLimbs() * fr.BitsPerLimb())
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(witnessValues); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	sum := frontend.Variable(1)
	for i := 0; i < len(vars); i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		diff := api.Sub(vars[i], composed)
		t := api.IsZero(diff)
		sum = api.And(sum, t)
	}

	return sum
}
