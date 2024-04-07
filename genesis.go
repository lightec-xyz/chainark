package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof  plonk.Proof[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	AcceptableFirstFp FingerPrint `gnark:",public"` // only there to keep the shape of genesis public witness in alignment with that of recursive

	GenesisID     LinkageID `gnark:",public"`
	FirstID       LinkageID
	SecondID      LinkageID         `gnark:",public"`
	FirstWitness  plonk.Witness[FR] // GenesisID -> FirstID
	SecondWitness plonk.Witness[FR] // FirstID -> SecondID

	// some constant values passed from outside
	UnitVkeyFpBytes FingerPrintBytes
}

// Note that AcceptableFirstFp is only there for shaping purpose, therefore no verification needed here
func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	// make sure we are using the correct Unit verification key
	fpFixed := FingerPrintFromBytes(c.UnitVkeyFpBytes, c.AcceptableFirstFp.BitsPerVar)

	// assert the first proof
	unit1 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.GenesisID,
		EndID:   c.FirstID,
	}
	err = unit1.AssertRelations(api, c.UnitVKey, c.FirstWitness, fpFixed)
	if err != nil {
		return err
	}

	// assert the second proof
	unit2 := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.FirstID,
		EndID:   c.SecondID,
	}
	err = unit2.AssertRelations(api, c.UnitVKey, c.SecondWitness, fpFixed)
	if err != nil {
		return err
	}

	return verifier.AssertSameProofs(
		c.UnitVKey,
		[]recursive_plonk.Proof[FR, G1El, G2El]{c.FirstProof, c.SecondProof},
		[]recursive_plonk.Witness[FR]{c.FirstWitness, c.SecondWitness},
		plonk.WithCompleteArithmetic())
}

func NewGenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes FingerPrintBytes) frontend.Circuit {
	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVKey:          recursive_plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		FirstProof:        recursive_plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		SecondProof:       recursive_plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		AcceptableFirstFp: PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),

		GenesisID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		FirstID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		SecondID:  PlaceholderLinkageID(nbIdVals, bitsPerIdVal),

		FirstWitness:  recursive_plonk.PlaceholderWitness[FR](ccsUnit),
		SecondWitness: recursive_plonk.PlaceholderWitness[FR](ccsUnit),

		UnitVkeyFpBytes: unitFpBytes,
	}
}

func NewGenesisAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	unitVkey recursive_plonk.VerifyingKey[FR, G1El, G2El],
	firstProof, secondProof recursive_plonk.Proof[FR, G1El, G2El],
	firstWitness, secondWitness recursive_plonk.Witness[FR],
	recursiveFp FingerPrint,
	genesisId, firstId, secondId LinkageID,
) frontend.Circuit {
	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVKey:          unitVkey,
		FirstProof:        firstProof,
		SecondProof:       secondProof,
		AcceptableFirstFp: recursiveFp,

		GenesisID: genesisId,
		FirstID:   firstId,
		SecondID:  secondId,

		FirstWitness:  firstWitness,
		SecondWitness: secondWitness,
	}
}
