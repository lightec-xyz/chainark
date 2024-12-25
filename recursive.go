package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

type RecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID `gnark:",public"`
	RelayID LinkageID
	EndID   LinkageID `gnark:",public"`

	SelfFp common_utils.FingerPrint `gnark:",public"`

	FirstVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof   plonk.Proof[FR, G1El, G2El]
	FirstWitness plonk.Witness[FR]

	SecondVKey    plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof   plonk.Proof[FR, G1El, G2El]
	SecondWitness plonk.Witness[FR]

	// constant values passed from outside
	ValidUnitFps []common_utils.FingerPrintBytes
}

// note that as we remove genesis, recursive could take in the first proof as unit, resulting in a genesis proof
func (c *RecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// verify the first vkey
	rp := recursiveProof[FR, G1El, G2El, GtEl]{
		beginID: c.BeginID,
		endID:   c.RelayID,
	}
	err := rp.assertRelations(api, c.FirstVKey, c.FirstWitness, c.SelfFp, c.ValidUnitFps)
	if err != nil {
		return err
	}

	// verify the second vkey
	err = assertVkeyInSet(api, c.SecondVKey, c.ValidUnitFps, c.SelfFp.BitsPerVar)
	if err != nil {
		return err
	}

	assertIds[FR](api, c.BeginID, c.RelayID, c.FirstWitness)
	assertIds[FR](api, c.RelayID, c.EndID, c.SecondWitness)

	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(c.FirstVKey, c.FirstProof, c.FirstWitness, plonk.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.SecondVKey, c.SecondProof, c.SecondWitness, plonk.WithCompleteArithmetic())
}

func NewRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes []common_utils.FingerPrintBytes) *RecursiveCircuit[FR, G1El, G2El, GtEl] {

	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		BeginID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		RelayID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),

		SelfFp: common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),

		FirstVKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		FirstProof:   plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		FirstWitness: plonk.PlaceholderWitness[FR](ccsUnit),

		SecondVKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		SecondProof:   plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		SecondWitness: plonk.PlaceholderWitness[FR](ccsUnit),

		ValidUnitFps: unitFpBytes,
	}
}

func NewRecursiveAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVkey, secondVkey plonk.VerifyingKey[FR, G1El, G2El],
	firstProof, secondProof plonk.Proof[FR, G1El, G2El],
	firstWitness, secondWitness plonk.Witness[FR],
	recursiveFp common_utils.FingerPrint,
	beginID, relayID, endID LinkageID,
) *RecursiveCircuit[FR, G1El, G2El, GtEl] {
	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		BeginID: beginID,
		RelayID: relayID,
		EndID:   endID,

		SelfFp: recursiveFp,

		FirstVKey:    firstVkey,
		FirstProof:   firstProof,
		FirstWitness: firstWitness,

		SecondVKey:    secondVkey,
		SecondProof:   secondProof,
		SecondWitness: secondWitness,
	}
}

type recursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	beginID LinkageID
	endID   LinkageID
}

func (rp *recursiveProof[FR, G1El, G2El, GtEl]) assertRelations(
	api frontend.API,
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	witness plonk.Witness[FR],
	selfFp common_utils.FingerPrint,
	validFps []common_utils.FingerPrintBytes) error {

	// 1. ensure that vkey.FingerPrint matches either one of the Unit VKey Fp, or the selfFp
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	vkeyFp, err := common_utils.FpValueOf(api, fp, selfFp.BitsPerVar)
	if err != nil {
		return err
	}

	recursiveFpTest := vkeyFp.IsEqual(api, selfFp)
	unitFpTest, err := testVKeyInSet(api, vkey, validFps, selfFp.BitsPerVar)
	if err != nil {
		return err
	}

	fpTest := api.Or(recursiveFpTest, unitFpTest)
	api.AssertIsEqual(fpTest, 1)

	// 2. ensure that we have been using the same selfFp IF a recursive circuit (not a unit)
	nbIdVars := len(rp.beginID.Vals) + len(rp.endID.Vals)
	nbFpVars := len(selfFp.Vals)
	wtnsTest := common_utils.TestFpWitness(api, selfFp, witness.Public[nbIdVars:nbIdVars+nbFpVars], uint(selfFp.BitsPerVar))
	api.AssertIsEqual(recursiveFpTest, wtnsTest)

	return nil
}
