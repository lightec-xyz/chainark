package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type GenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	UnitVk          plonk.VerifyingKey[FR, G1El, G2El]
	UnitProof       plonk.Proof[FR, G1El, G2El]
	UnitWit         plonk.Witness[FR]
	AcceptableFp    FingerPrint       `gnark:",public"` // only there to keep the shape of genesis public witness in alignment with that of recursive
	BeginID         LinkageID         `gnark:",public"`
	EndID           LinkageID         `gnark:",public"`
	NbIDs           frontend.Variable `gnark:",public"`
	NbBitsPerFpVar  int
	AcceptableVkFps []FingerPrintBytes // only there to keep the shape of genesis public witness in alignment with that of recursive
}

// Note that AcceptableFirstFp is only there for shaping purpose, therefore no verification needed here
func (c *GenesisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	fpVar, err := c.UnitVk.FingerPrint(api)
	if err != nil {
		return err
	}

	AssertFpInSet(api, fpVar, c.AcceptableVkFps, int(c.NbBitsPerFpVar))

	nbIDVals := len(c.BeginID.Vals)
	AssertIDWitness(api, c.BeginID, c.UnitWit.Public[:nbIDVals], uint(c.BeginID.BitsPerVar))
	AssertIDWitness(api, c.EndID, c.UnitWit.Public[nbIDVals:nbIDVals*2], uint(c.EndID.BitsPerVar))
	nbIDs := RetrieveU32ValueFromElement[FR](api, c.UnitWit.Public[nbIDVals*2])
	api.AssertIsEqual(c.NbIDs, nbIDs)

	return verifier.AssertProof(c.UnitVk, c.UnitProof, c.UnitWit, plonk.WithCompleteArithmetic())
}

func NewGenesisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIDVals, nbBitsPerIDVal, nbFpVals, nbBitsPerFpVal int,
	unitCcs constraint.ConstraintSystem,
	acceptableVkFps []FingerPrintBytes) frontend.Circuit {

	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVk:          plonk.PlaceholderVerifyingKey[FR, G1El, G2El](unitCcs),
		UnitProof:       plonk.PlaceholderProof[FR, G1El, G2El](unitCcs),
		UnitWit:         plonk.PlaceholderWitness[FR](unitCcs),
		AcceptableFp:    PlaceholderFingerPrint(nbFpVals, nbBitsPerFpVal),
		BeginID:         PlaceholderLinkageID(nbIDVals, nbBitsPerIDVal),
		EndID:           PlaceholderLinkageID(nbIDVals, nbBitsPerIDVal),
		NbBitsPerFpVar:  nbBitsPerFpVal,
		AcceptableVkFps: acceptableVkFps,
	}
}

func NewGenesisAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	vk plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	wit plonk.Witness[FR],
	recursiveFp FingerPrint,
	beginID, endID LinkageID,
	nbIDs int,
) frontend.Circuit {

	return &GenesisCircuit[FR, G1El, G2El, GtEl]{
		UnitVk:       vk,
		UnitProof:    proof,
		UnitWit:      wit,
		AcceptableFp: recursiveFp,
		BeginID:      beginID,
		EndID:        endID,
		NbIDs:        nbIDs,
	}
}
