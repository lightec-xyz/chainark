package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type UnitProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID        LinkageID
	EndID          LinkageID
	NbIDs          frontend.Variable
	UnitVkFpBytes  []FingerPrintBytes
	NbBitsPerFpVar int
}

func (_proof *UnitProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vk plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	witness plonk.Witness[FR],
) error {

	//1. ensure that we are using the correct verification key
	fpVar, err := vk.FingerPrint(api)
	if err != nil {
		return err
	}
	AssertFpInSet(api, fpVar, _proof.UnitVkFpBytes, _proof.NbBitsPerFpVar)

	//2. constraint witness against BeginID & EndID
	nbIDVals := len(_proof.BeginID.Vals)
	AssertIDWitness(api, _proof.BeginID, witness.Public[:nbIDVals], uint(_proof.BeginID.BitsPerVar))
	AssertIDWitness(api, _proof.EndID, witness.Public[nbIDVals:nbIDVals*2], uint(_proof.EndID.BitsPerVar))

	//3. constraint witness against NbIDs
	nbIDs := RetrieveU32ValueFromElement[FR](api, witness.Public[nbIDVals*2])
	api.AssertIsEqual(_proof.NbIDs, nbIDs)

	//4. assert proof
	return verifier.AssertProof(vk, proof, witness, plonk.WithCompleteArithmetic())
}
