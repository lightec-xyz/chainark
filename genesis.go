package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof  plonk.Proof[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	AcceptableFirstFp FingerPrint[FR] `gnark:",public"` // only there to keep the shape of genesis public witness in alignment with that of recursive

	GenesisID     LinkageID[FR] `gnark:",public"`
	FirstID       LinkageID[FR]
	SecondID      LinkageID[FR]     `gnark:",public"`
	FirstWitness  plonk.Witness[FR] // GenesisID -> FirstID
	SecondWitness plonk.Witness[FR] // FirstID -> SecondID

	// some constant values passed from outside
	UnitVkeyFpBytes FingerPrintBytes

	// some data field needs from outside
	InnerField *big.Int `gnark:"-"`
}

// TODO aggregated verification optimization
// Note that AcceptableFirstFp is only there for shaping purpose, therefore no verification needed here
func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	// make sure we are using the correct Unit verification key
	fpFixed := FingerPrintFromBytes[FR](c.UnitVkeyFpBytes, c.AcceptableFirstFp.BitsPerElement)

	// assert the first proof
	unit1 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.GenesisID,
		EndID:   c.FirstID,
	}
	err = unit1.Assert(api, verifier, c.UnitVKey, c.FirstProof, c.FirstWitness, fpFixed)
	if err != nil {
		return err
	}

	// assert the second proof
	unit2 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.FirstID,
		EndID:   c.SecondID,
	}
	return unit2.Assert(api, verifier, c.UnitVKey, c.SecondProof, c.SecondWitness, fpFixed)
}
