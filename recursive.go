package chainark

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

type MultiRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID `gnark:",public"`
	RelayID LinkageID
	EndID   LinkageID `gnark:",public"`

	SelfFps []common_utils.FingerPrint[FR] `gnark:",public"`

	FirstVKey    plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof   plonk.Proof[FR, G1El, G2El]
	FirstWitness plonk.Witness[FR]

	SecondVKey    plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof   plonk.Proof[FR, G1El, G2El]
	SecondWitness plonk.Witness[FR]

	// constant values passed from outside
	ValidUnitFps []common_utils.FingerPrintBytes
	NbSelfFps    int

	optimization bool
}

func (c *MultiRecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// verify the first vkey
	rp := recursiveProof[FR, G1El, G2El, GtEl]{
		beginID:   c.BeginID,
		endID:     c.RelayID,
		nbSelfFps: c.NbSelfFps,
	}
	err := rp.assertRelations(api, c.FirstVKey, c.FirstWitness, c.SelfFps, c.ValidUnitFps)
	if err != nil {
		return err
	}

	// verify the second vkey
	secondFp, err := c.SecondVKey.FingerPrint(api)
	if err != nil {
		return err
	}
	common_utils.AssertFpInSet[FR](api, secondFp, c.ValidUnitFps)

	assertIds[FR](api, c.BeginID, c.RelayID, c.FirstWitness)
	assertIds[FR](api, c.RelayID, c.EndID, c.SecondWitness)

	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	if c.optimization {
		return verifier.AssertDifferentProofs(c.FirstVKey.BaseVerifyingKey,
			[]plonk.CircuitVerifyingKey[FR, G1El]{c.FirstVKey.CircuitVerifyingKey, c.SecondVKey.CircuitVerifyingKey},
			[]frontend.Variable{0, 1},
			[]plonk.Proof[FR, G1El, G2El]{c.FirstProof, c.SecondProof},
			[]plonk.Witness[FR]{c.FirstWitness, c.SecondWitness},
			plonk.WithCompleteArithmetic(),
		)
	} else {
		err = verifier.AssertProof(c.FirstVKey, c.FirstProof, c.FirstWitness, plonk.WithCompleteArithmetic())
		if err != nil {
			return err
		}
		return verifier.AssertProof(c.SecondVKey, c.SecondProof, c.SecondWitness, plonk.WithCompleteArithmetic())
	}
}

func NewMultiRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes []common_utils.FingerPrintBytes, nbSelfFps int,
	opt ...bool) *MultiRecursiveCircuit[FR, G1El, G2El, GtEl] {

	optm := false
	if len(opt) != 0 {
		optm = opt[0]
	}

	if nbSelfFps <= 0 {
		panic("wrong nbSelfFps")
	}
	selfFps := make([]common_utils.FingerPrint[FR], nbSelfFps)

	return &MultiRecursiveCircuit[FR, G1El, G2El, GtEl]{
		BeginID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		RelayID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),

		SelfFps: selfFps,

		FirstVKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		FirstProof:   plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		FirstWitness: plonk.PlaceholderWitness[FR](ccsUnit),

		SecondVKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccsUnit),
		SecondProof:   plonk.PlaceholderProof[FR, G1El, G2El](ccsUnit),
		SecondWitness: plonk.PlaceholderWitness[FR](ccsUnit),

		ValidUnitFps: unitFpBytes,
		NbSelfFps:    nbSelfFps,
		optimization: optm,
	}
}

func NewMultiRecursiveAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVkey, secondVkey plonk.VerifyingKey[FR, G1El, G2El],
	firstProof, secondProof plonk.Proof[FR, G1El, G2El],
	firstWitness, secondWitness plonk.Witness[FR],
	recursiveFps []common_utils.FingerPrint[FR],
	beginID, relayID, endID LinkageID,
) *MultiRecursiveCircuit[FR, G1El, G2El, GtEl] {
	return &MultiRecursiveCircuit[FR, G1El, G2El, GtEl]{
		BeginID: beginID,
		RelayID: relayID,
		EndID:   endID,

		SelfFps: recursiveFps,

		FirstVKey:    firstVkey,
		FirstProof:   firstProof,
		FirstWitness: firstWitness,

		SecondVKey:    secondVkey,
		SecondProof:   secondProof,
		SecondWitness: secondWitness,
	}
}

type RecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	*MultiRecursiveCircuit[FR, G1El, G2El, GtEl]
}

// note that as we remove genesis, recursive could take in the first proof as unit, resulting in a genesis proof
func (c *RecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return c.MultiRecursiveCircuit.Define(api)
}

func NewRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes []common_utils.FingerPrintBytes,
	opt ...bool) *RecursiveCircuit[FR, G1El, G2El, GtEl] {

	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		MultiRecursiveCircuit: NewMultiRecursiveCircuit[FR, G1El, G2El, GtEl](
			nbIdVals, bitsPerIdVal,
			ccsUnit,
			unitFpBytes, 1,
			opt...),
	}
}

func NewRecursiveAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVkey, secondVkey plonk.VerifyingKey[FR, G1El, G2El],
	firstProof, secondProof plonk.Proof[FR, G1El, G2El],
	firstWitness, secondWitness plonk.Witness[FR],
	recursiveFp common_utils.FingerPrint[FR],
	beginID, relayID, endID LinkageID,
) *RecursiveCircuit[FR, G1El, G2El, GtEl] {
	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		MultiRecursiveCircuit: NewMultiRecursiveAssignment[FR, G1El, G2El, GtEl](
			firstVkey, secondVkey,
			firstProof, secondProof,
			firstWitness, secondWitness,
			[]common_utils.FingerPrint[FR]{recursiveFp},
			beginID, relayID, endID,
		),
	}
}

type recursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	beginID   LinkageID
	endID     LinkageID
	nbSelfFps int
}

func (rp *recursiveProof[FR, G1El, G2El, GtEl]) assertRelations(
	api frontend.API,
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	witness plonk.Witness[FR],
	selfFps []common_utils.FingerPrint[FR],
	unitFps []common_utils.FingerPrintBytes) error {

	// 1. ensure that vkey.FingerPrint matches either one of the Unit VKey Fp, or one of the selfFps
	vkeyFp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	recursiveFpTest := common_utils.TestFpInFpSet[FR](api, vkeyFp, selfFps)

	unitFpTest := common_utils.TestFpInSet[FR](api, vkeyFp, unitFps)

	fpTest := api.Or(recursiveFpTest, unitFpTest)
	api.AssertIsEqual(fpTest, 1)

	// 2. ensure that we have been using the same set of selfFps IF a recursive circuit
	nbIdVars := len(rp.beginID.Vals) + len(rp.endID.Vals)
	nbFpVars := 1

	setTest := TestRecursiveFps[FR](api, witness, selfFps, nbIdVars, nbFpVars, rp.nbSelfFps)
	api.AssertIsEqual(recursiveFpTest, setTest)

	return nil
}

func TestRecursiveFps[FR emulated.FieldParams](api frontend.API, witness plonk.Witness[FR], selfFps []common_utils.FingerPrint[FR],
	nbIdVars, nbFpVars, nbSelfFps int) frontend.Variable {

	test := frontend.Variable(1)
	for i := 0; i < nbSelfFps; i++ {
		begin := nbIdVars + i*nbFpVars
		end := begin + nbFpVars
		t := common_utils.TestFpWitness(api, selfFps[i], witness.Public[begin:end])
		test = api.And(test, t)
	}
	return test
}
