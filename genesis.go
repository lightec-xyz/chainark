package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof  plonk.Proof[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	AcceptableFirstFp FingerPrint `gnark:",public"` // only there to keep the genesis public witness in alignment with that of recursive

	GenesisID LinkageID `gnark:",public"`
	FirstID   LinkageID
	SecondID  LinkageID `gnark:",public"`

	// some constant values passed from outside
	UnitFpBytes    FingerPrintBytes
	GenesisIDBytes LinkageIDBytes

	// some data field needs from outside
	innerField     *big.Int
	unitAssignment UnitCircuitPublicAssignment[FR, G1El, G2El, GtEl]
}

func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	fpTest := c.AcceptableFirstFp.IsEqual(api, uints.NewU8Array(c.UnitFpBytes))
	api.AssertIsEqual(fpTest, 1)

	// assert the first proof
	unit1 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.GenesisID,
		EndID:   c.FirstID,
	}
	unit1.Assert(api, verifier, c.UnitVKey, c.UnitFpBytes, c.FirstProof, c.unitAssignment, c.innerField)
	if err != nil {
		return err
	}

	// assert the second proof
	// TODO the unit vkey fp assertion is run twice
	unit2 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.FirstID,
		EndID:   c.SecondID,
	}
	return unit2.Assert(api, verifier, c.UnitVKey, c.UnitFpBytes, c.SecondProof, c.unitAssignment, c.innerField)
}
