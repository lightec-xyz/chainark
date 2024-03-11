package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVKey    plonk.VerifyingKey[FR, G1El, G2El] // this could be constant, and provided during circuit compilation (avoid finger print verification)
	FirstProof  plonk.Proof[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	AcceptableFirstFp FingerPrint[FR] `gnark:",public"` // only there to keep the genesis public witness in alignment with that of recursive

	GenesisID     LinkageID[FR] `gnark:",public"`
	FirstID       LinkageID[FR]
	SecondID      LinkageID[FR]     `gnark:",public"`
	FirstWitness  plonk.Witness[FR] // GenesisID -> FirstID
	SecondWitness plonk.Witness[FR] // FirstID -> SecondID

	// some constant values passed from outside
	UnitVkeyFpBytes FingerPrintBytes
	GenesisIDBytes  LinkageIDBytes

	// some data field needs from outside
	InnerField *big.Int `gnark:"-"`
}

func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	vkeyFp, err := c.UnitVKey.FingerPrint(api)
	if err != nil {
		return err
	}
	fp, err := FpValueOf[FR](api, vkeyFp, c.AcceptableFirstFp.BitsPerElement)
	if err != nil {
		return err
	}
	c.AcceptableFirstFp.AssertIsEqual(api, fp)

	// TODO aggregated verification

	fpFixed := FingerPrintFromBytes[FR](c.UnitVkeyFpBytes, c.AcceptableFirstFp.BitsPerElement)

	// assert the first proof
	unit1 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.GenesisID,
		EndID:   c.FirstID,
	}
	err = unit1.Assert(api, verifier, c.UnitVKey, c.FirstProof, c.FirstWitness, fpFixed, c.InnerField)
	if err != nil {
		return err
	}

	// assert the second proof
	unit2 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.FirstID,
		EndID:   c.SecondID,
	}
	return unit2.Assert(api, verifier, c.UnitVKey, c.SecondProof, c.SecondWitness, fpFixed, c.InnerField)
}
