package chainark

import (
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
	fpFixed FingerPrint[FR]) error {

	// ensure that we are using the correct verification key
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	vkeyFp, err := FpValueOf[FR](api, fp, fpFixed.BitsPerElement)
	fpFixed.AssertIsEqual(api, vkeyFp)

	// constraint witness against BeginID & EndID
	nbEles := len(up.BeginID.Vals)
	nbLimbs := len(up.BeginID.Vals[0].Limbs)
	err = AssertIDWitness[FR](api, up.BeginID, witness.Public[:nbEles*nbLimbs])
	if err != nil {
		return err
	}
	err = AssertIDWitness[FR](api, up.EndID, witness.Public[nbEles*nbLimbs:])
	if err != nil {
		return err
	}

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
