package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type RecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	FirstVk           plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof        plonk.Proof[FR, G1El, G2El]
	AcceptableFirstFp FingerPrint `gnark:",public"` //FIXME(keep), recursive Fp?
	SecondVk          plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof       plonk.Proof[FR, G1El, G2El]
	BeginID           LinkageID `gnark:",public"`
	RelayID           LinkageID
	EndID             LinkageID `gnark:",public"`
	NbIDsInFirstWit   frontend.Variable
	NbIDsInSecondWit  frontend.Variable
	NbIDs             frontend.Variable `gnark:",public"`
	FirstWitness      plonk.Witness[FR]
	SecondWitness     plonk.Witness[FR]
	// some constant values passed from outside
	GenesisVkFpBytes FingerPrintBytes
	UnitVkFpBytes    []FingerPrintBytes
}

func (c *RecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	//1. assert the first proof, the first proof should be genesis or recursive proof
	gOrR := GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]{
		BeginID: c.BeginID,
		EndID:   c.RelayID,
		NbIDs:   c.NbIDsInFirstWit,
	}
	err = gOrR.Assert(api, verifier, c.FirstVk, c.FirstWitness, c.AcceptableFirstFp, c.GenesisVkFpBytes, c.FirstProof)
	if err != nil {
		return err
	}

	//2. assert the second proof, the second proof should be unit proof
	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID:        c.RelayID,
		EndID:          c.EndID,
		NbIDs:          c.NbIDsInSecondWit,
		UnitVkFpBytes:  c.UnitVkFpBytes,
		NbBitsPerFpVar: c.AcceptableFirstFp.BitsPerVar,
	}
	err = unit.Assert(api, verifier, c.SecondVk, c.SecondProof, c.SecondWitness)
	if err != nil {
		return err
	}

	//3. assert c.NbIDInFirstWit + c.NbIDInSecondWit = c.NbIDs
	nbIDs := api.Add(c.NbIDsInFirstWit, c.NbIDsInSecondWit)
	api.AssertIsEqual(c.NbIDs, nbIDs)

	return nil
}

func NewRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIDVals, nbBitsPerIdVal, nbFpVals, nbBitsPerFpVal int,
	unitCcs, genesisCcs constraint.ConstraintSystem,
	genesisVkFpBytes FingerPrintBytes,
	unitVkFpBytes []FingerPrintBytes) frontend.Circuit {

	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		FirstVk:           plonk.PlaceholderVerifyingKey[FR, G1El, G2El](genesisCcs),
		FirstProof:        plonk.PlaceholderProof[FR, G1El, G2El](genesisCcs),
		AcceptableFirstFp: PlaceholderFingerPrint(nbFpVals, nbBitsPerFpVal),
		SecondVk:          plonk.PlaceholderVerifyingKey[FR, G1El, G2El](unitCcs),
		SecondProof:       plonk.PlaceholderProof[FR, G1El, G2El](unitCcs),
		BeginID:           PlaceholderLinkageID(nbIDVals, nbBitsPerIdVal),
		RelayID:           PlaceholderLinkageID(nbIDVals, nbBitsPerIdVal),
		EndID:             PlaceholderLinkageID(nbIDVals, nbBitsPerIdVal),
		FirstWitness:      plonk.PlaceholderWitness[FR](genesisCcs),
		SecondWitness:     plonk.PlaceholderWitness[FR](unitCcs),

		UnitVkFpBytes:    unitVkFpBytes,
		GenesisVkFpBytes: genesisVkFpBytes,
	}
}

func NewRecursiveAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVk, secondVk plonk.VerifyingKey[FR, G1El, G2El],
	firstProof, secondProof plonk.Proof[FR, G1El, G2El],
	firstWitness, secondWitness plonk.Witness[FR],
	recursiveFp FingerPrint,
	beginID, relayID, endID LinkageID,
	nbIDsInFirstWit, nbIDsInSecondWit, nbIDs frontend.Variable,
) frontend.Circuit {
	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		FirstVk:           firstVk,
		FirstProof:        firstProof,
		AcceptableFirstFp: recursiveFp,
		SecondVk:          secondVk,
		SecondProof:       secondProof,
		BeginID:           beginID,
		RelayID:           relayID,
		EndID:             endID,
		FirstWitness:      firstWitness,
		SecondWitness:     secondWitness,
		NbIDsInFirstWit:   nbIDsInFirstWit,
		NbIDsInSecondWit:  nbIDsInSecondWit,
		NbIDs:             nbIDs,
	}
}

type GenesisOrRecursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID
	EndID   LinkageID
	NbIDs   frontend.Variable
}

func (prf *GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vk plonk.VerifyingKey[FR, G1El, G2El],
	witness plonk.Witness[FR],
	recursiveVkFp FingerPrint,
	genesisVkFpBytes FingerPrintBytes,
	proof plonk.Proof[FR, G1El, G2El]) error {

	// see README / Soundness Diagram for detailed security analysis
	// 1. ensure that vkey.FingerPrint matches either the hardcoded Genesis VKey Fp, or the recursiveFp
	fpVar, err := vk.FingerPrint(api)
	if err != nil {
		return err
	}

	fp, err := FpValueOf(api, fpVar, recursiveVkFp.BitsPerVar)
	if err != nil {
		return err
	}

	isRecursiveVkFp := fp.IsEqual(api, recursiveVkFp)

	genesisVkFp := FingerPrintFromBytes(genesisVkFpBytes, recursiveVkFp.BitsPerVar)
	isGenesisVkFp := fp.IsEqual(api, genesisVkFp)

	firstVkTest := api.Or(isRecursiveVkFp, isGenesisVkFp)
	api.AssertIsEqual(firstVkTest, 1)

	// 2. ensure that we have been using the same recursiveVkFp value, that is, constraint witness against acceptableFp
	nbFpVars := len(recursiveVkFp.Vals)
	AssertFpWitness(api, recursiveVkFp, witness.Public[:nbFpVars], uint(recursiveVkFp.BitsPerVar))

	// 3. constraint witness against BeginID & EndID
	nbIDVals := len(prf.BeginID.Vals)
	AssertIDWitness[FR](api, prf.BeginID, witness.Public[nbFpVars:nbFpVars+nbIDVals], uint(prf.BeginID.BitsPerVar))
	AssertIDWitness[FR](api, prf.EndID, witness.Public[nbFpVars+nbIDVals:nbFpVars+nbIDVals*2], uint(prf.EndID.BitsPerVar))

	// 4. constraint witness against NbIDs
	nbIDs := RetrieveU32ValueFromElement[FR](api, witness.Public[nbFpVars+nbIDVals*2])
	api.AssertIsEqual(prf.NbIDs, nbIDs)

	return verifier.AssertProof(vk, proof, witness, plonk.WithCompleteArithmetic())
}
