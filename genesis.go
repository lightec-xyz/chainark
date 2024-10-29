package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVKey    plonk.VerifyingKey[FR, G1El, G2El]
	UnitProof   plonk.Proof[FR, G1El, G2El]
	UnitWitness plonk.Witness[FR]

	AcceptableFirstFp FingerPrint `gnark:",public"` // only there to keep the shape of genesis public witness in alignment with that of recursive

	GenesisID LinkageID `gnark:",public"`
	SecondID  LinkageID `gnark:",public"`

	// some constant values passed from outside
	ValidUnitFps []FingerPrintBytes
}

// Note that AcceptableFirstFp is only there for shaping purpose, therefore no verification needed here
func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.GenesisID,
		EndID:   c.SecondID,
	}
	return unit.AssertRelations(api, verifier, c.UnitVKey, c.UnitProof, c.UnitWitness, c.ValidUnitFps, c.AcceptableFirstFp.BitsPerVar)
}

func NewGenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
	ccsUnit constraint.ConstraintSystem,
	validFps []FingerPrintBytes) frontend.Circuit {

	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVKey:          plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		UnitProof:         plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		UnitWitness:       plonk.PlaceholderWitness[FR](ccsUnit),
		AcceptableFirstFp: PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),

		GenesisID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		SecondID:  PlaceholderLinkageID(nbIdVals, bitsPerIdVal),

		ValidUnitFps: validFps,
	}
}

func NewGenesisAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	witness plonk.Witness[FR],
	recursiveFp FingerPrint,
	genesisID, secondID LinkageID,
) frontend.Circuit {

	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVKey:          vkey,
		UnitProof:         proof,
		UnitWitness:       witness,
		AcceptableFirstFp: recursiveFp,

		GenesisID: genesisID,
		SecondID:  secondID,
	}
}
