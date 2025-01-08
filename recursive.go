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

	SelfFps []common_utils.FingerPrint `gnark:",public"`

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
	err = assertVkeyInSet(api, c.SecondVKey, c.ValidUnitFps, c.SelfFps[0].BitsPerVar)
	if err != nil {
		return err
	}

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
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
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
	selfFps := make([]common_utils.FingerPrint, nbSelfFps)
	for i := 0; i < nbSelfFps; i++ {
		selfFps[i] = common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal)
	}

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
	recursiveFps []common_utils.FingerPrint,
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
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
	ccsUnit constraint.ConstraintSystem,
	unitFpBytes []common_utils.FingerPrintBytes,
	opt ...bool) *RecursiveCircuit[FR, G1El, G2El, GtEl] {

	return &RecursiveCircuit[FR, G1El, G2El, GtEl]{
		MultiRecursiveCircuit: NewMultiRecursiveCircuit[FR, G1El, G2El, GtEl](
			nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal,
			ccsUnit,
			unitFpBytes, 1,
			opt...),
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
		MultiRecursiveCircuit: NewMultiRecursiveAssignment[FR, G1El, G2El, GtEl](
			firstVkey, secondVkey,
			firstProof, secondProof,
			firstWitness, secondWitness,
			[]common_utils.FingerPrint{recursiveFp},
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
	selfFps []common_utils.FingerPrint,
	unitFps []common_utils.FingerPrintBytes) error {

	// 1. ensure that vkey.FingerPrint matches either one of the Unit VKey Fp, or one of the selfFps
	recursiveFpTest := frontend.Variable(0)
	for i := 0; i < rp.nbSelfFps; i++ {
		test, err := common_utils.TestVkeyFp[FR, G1El, G2El, GtEl](api, vkey, selfFps[i])
		if err != nil {
			return err
		}
		recursiveFpTest = api.Or(recursiveFpTest, test)
	}

	unitFpTest, err := testVKeyInSet(api, vkey, unitFps, selfFps[0].BitsPerVar)
	if err != nil {
		return err
	}

	fpTest := api.Or(recursiveFpTest, unitFpTest)
	api.AssertIsEqual(fpTest, 1)

	// 2. ensure that we have been using the same set of selfFps IF a recursive circuit
	nbIdVars := len(rp.beginID.Vals) + len(rp.endID.Vals)
	nbFpVars := len(selfFps[0].Vals)

	setTest := frontend.Variable(1)
	for i := 0; i < rp.nbSelfFps; i++ {
		begin := nbIdVars + i*nbFpVars
		end := begin + nbFpVars
		test := common_utils.TestFpWitness(api, selfFps[i], witness.Public[begin:end], uint(selfFps[0].BitsPerVar))
		setTest = api.And(setTest, test)
	}
	api.AssertIsEqual(recursiveFpTest, setTest)

	return nil
}
