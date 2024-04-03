package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type UnitProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID
	EndID   LinkageID
}

func (up *UnitProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	witness plonk.Witness[FR],
	fpFixed FingerPrint) error {

	// ensure that we are using the correct verification key
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	vkeyFp, err := FpValueOf(api, fp, fpFixed.BitsPerVar)
	fpFixed.AssertIsEqual(api, vkeyFp)

	// constraint witness against BeginID & EndID
	nbVars := len(up.BeginID.Vals)
	AssertIDWitness(api, up.BeginID, witness.Public[:nbVars], uint(up.BeginID.BitsPerVar))
	AssertIDWitness(api, up.EndID, witness.Public[nbVars:], uint(up.EndID.BitsPerVar))

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
