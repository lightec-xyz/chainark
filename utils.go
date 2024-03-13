package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// FIXME skip actual value assertion for now
func assertIDWitness[FR emulated.FieldParams](api frontend.API, id LinkageID[FR], witnessValues []emulated.Element[FR]) error {
	api.AssertIsEqual(len(witnessValues), len(id.Vals)*len(id.Vals[0].Limbs))
	// field, err := emulated.NewField[FR](api)
	// if err != nil {
	// 	return err
	// }

	for i := 0; i < len(id.Vals); i++ {
		for j := 0; j < len(id.Vals[0].Limbs); j++ {
			// l := id.BitsPerElement / len(id.Vals[0].Limbs)
			vId := id.Vals[i].Limbs[j]
			api.Println(vId)

			vWit := witnessValues[i*len(id.Vals)+j]
			api.Println(vWit)
		}
	}

	return nil
}

func assertFpWitness[FR emulated.FieldParams](api frontend.API, fp FingerPrint[FR], witnessValues []emulated.Element[FR]) error {
	api.AssertIsEqual(len(witnessValues), len(fp.Vals)*len(fp.Vals[0].Limbs))
	// field, err := emulated.NewField[FR](api)
	// if err != nil {
	// 	return err
	// }

	for i := 0; i < len(fp.Vals); i++ {
		for j := 0; j < len(fp.Vals[0].Limbs); j++ {
			// l := id.BitsPerElement / len(id.Vals[0].Limbs)
			vId := fp.Vals[i].Limbs[j]
			api.Println(vId)

			vWit := witnessValues[i*len(fp.Vals)+j]
			api.Println(vWit)
		}
	}

	return nil
}
