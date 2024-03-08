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
	wBegin := LinkageID[FR]{
		Vals:           witness.Public[:vLen],
		BitsPerElement: up.BeginID.BitsPerElement,
	}
	up.BeginID.AssertIsEqual(api, wBegin)
	wEnd := LinkageID[FR]{
		Vals:           witness.Public[vLen : vLen*2],
		BitsPerElement: up.EndID.BitsPerElement,
	}
	up.EndID.AssertIsEqual(api, wEnd)

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
