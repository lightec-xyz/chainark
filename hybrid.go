package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

type HybridCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID `gnark:",public"`
	RelayID LinkageID
	EndID   LinkageID `gnark:",public"`

	SelfFps []common_utils.FingerPrint `gnark:",public"`

	FirstVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof   plonk.Proof[FR, G1El, G2El]
	FirstWitness plonk.Witness[FR]

	SecondComp *UnitCore[FR, G1El, G2El, GtEl]

	// constant values passed from outside
	ValidUnitFps []common_utils.FingerPrintBytes
	NbSelfFps    int
}

func (c *HybridCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// verify the first vkey
	rp := recursiveProof[FR, G1El, G2El, GtEl]{
		beginID: c.BeginID,
		endID:   c.RelayID,
	}
	err := rp.assertRelations(api, c.FirstVKey, c.FirstWitness, c.SelfFps, c.ValidUnitFps)
	if err != nil {
		return err
	}

	assertIds[FR](api, c.BeginID, c.RelayID, c.FirstWitness)

	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(c.FirstVKey, c.FirstProof, c.FirstWitness, plonk.WithCompleteArithmetic())
	if err != nil {
		return err
	}

	// linking relayId to endId
	c.RelayID.AssertIsEqual(api, c.SecondComp.BeginID)
	c.EndID.AssertIsEqual(api, c.SecondComp.EndID)

	return c.SecondComp.Define(api)
}
