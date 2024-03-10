package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type UnitProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID[FR]
	EndID   LinkageID[FR]
}

func (up *UnitProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	witness plonk.Witness[FR],
	field *big.Int) error {

	// constraint witness against BeginID & EndID
	vLen := len(up.BeginID.Vals)
	lLen := len(up.BeginID.Vals[0].Limbs)
	err := assertWitness[FR](api, up.BeginID, witness.Public[:vLen*lLen])
	if err != nil {
		return err
	}
	err = assertWitness[FR](api, up.EndID, witness.Public[vLen*lLen:])
	if err != nil {
		return err
	}

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}

// TODO optimization
// FIXME some issues preventing recursive circuit definition and witness value extraction, so skip actual value assertion for now
func assertWitness[FR emulated.FieldParams](api frontend.API, id LinkageID[FR], witnessValues []emulated.Element[FR]) error {
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
