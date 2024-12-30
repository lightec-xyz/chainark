package chainark

import (
	"github.com/consensys/gnark/constraint"
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

	SecondComp UnitCore[FR, G1El, G2El, GtEl]

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
	c.RelayID.AssertIsEqual(api, c.SecondComp.GetBeginID())
	c.EndID.AssertIsEqual(api, c.SecondComp.GetEndID())

	return c.SecondComp.Define(api)
}

func NewHybridCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes []common_utils.FingerPrintBytes, nbSelfFps int,
	extraComp UnitCore[FR, G1El, G2El, GtEl],
) *HybridCircuit[FR, G1El, G2El, GtEl] {

	if nbSelfFps <= 0 {
		panic("wrong nbSelfFps")
	}
	selfFps := make([]common_utils.FingerPrint, nbSelfFps)
	for i := 0; i < nbSelfFps; i++ {
		selfFps[i] = common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal)
	}

	return &HybridCircuit[FR, G1El, G2El, GtEl]{
		BeginID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		RelayID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),

		SelfFps: selfFps,

		FirstVKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		FirstProof:   plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		FirstWitness: plonk.PlaceholderWitness[FR](ccsUnit),

		SecondComp: extraComp,

		ValidUnitFps: unitFpBytes,
		NbSelfFps:    nbSelfFps,
	}
}

func NewHybridAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVkey plonk.VerifyingKey[FR, G1El, G2El],
	firstProof plonk.Proof[FR, G1El, G2El],
	firstWitness plonk.Witness[FR],
	recursiveFps []common_utils.FingerPrint,
	beginID, relayID, endID LinkageID,
	extraComp UnitCore[FR, G1El, G2El, GtEl],
) *HybridCircuit[FR, G1El, G2El, GtEl] {
	return &HybridCircuit[FR, G1El, G2El, GtEl]{
		BeginID: beginID,
		RelayID: relayID,
		EndID:   endID,

		SelfFps: recursiveFps,

		FirstVKey:    firstVkey,
		FirstProof:   firstProof,
		FirstWitness: firstWitness,

		SecondComp: extraComp,
	}
}
