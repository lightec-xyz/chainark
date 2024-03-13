package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func assertIDWitness[FR emulated.FieldParams](api frontend.API, id LinkageID[FR], witnessValues []emulated.Element[FR]) error {
	return assertElementsVSWitness[FR](api, id.Vals, witnessValues)
}

func assertFpWitness[FR emulated.FieldParams](api frontend.API, fp FingerPrint[FR], witnessValues []emulated.Element[FR]) error {
	return assertElementsVSWitness[FR](api, fp.Vals, witnessValues)
}

func assertElementsVSWitness[FR emulated.FieldParams](api frontend.API, eles []emulated.Element[FR], witnessValues []emulated.Element[FR]) error {
	nbEles := len(eles)
	nbLimbsPerEle := len(eles[0].Limbs)
	api.AssertIsEqual(len(witnessValues), nbEles*nbLimbsPerEle)

	for i := 0; i < nbEles; i++ {
		for j := 0; j < nbLimbsPerEle; j++ {
			ele := eles[i].Limbs[j]
			wLimbs := witnessValues[i*nbLimbsPerEle+j].Limbs

			api.AssertIsEqual(ele, wLimbs[0])
			for k := 1; k < len(wLimbs); k++ {
				api.AssertIsEqual(wLimbs[k], 0)
			}
		}
	}

	return nil

}
