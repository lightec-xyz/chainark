package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type RecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	FirstVKey         plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof        plonk.Proof[FR, G1El, G2El]
	AcceptableFirstFp FingerPrint `gnark:",public"`

	SecondVKey  plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	BeginID LinkageID `gnark:",public"`
	RelayID LinkageID
	EndID   LinkageID `gnark:",public"`

	FirstWitness  plonk.Witness[FR]
	SecondWitness plonk.Witness[FR]

	// some constant values passed from outside
	GenesisFpBytes  FingerPrintBytes
	UnitVKeyFpBytes FingerPrintBytes

	// some data field needs from outside
	InnerField *big.Int
}

func (c *RecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	// assert the first proof
	gOrR := GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]{
		BeginID: c.BeginID,
		EndID:   c.RelayID,
	}
	err = gOrR.Assert(api, verifier, c.FirstVKey, c.FirstWitness, c.AcceptableFirstFp, c.GenesisFpBytes,
		c.UnitVKeyFpBytes, c.FirstProof, c.InnerField)
	if err != nil {
		return err
	}

	// assert the second proof.
	fpFixed := FingerPrintFromBytes(c.UnitVKeyFpBytes, c.AcceptableFirstFp.BitsPerVar)
	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.RelayID,
		EndID:   c.EndID,
	}
	return unit.Assert(api, verifier, c.SecondVKey, c.SecondProof, c.SecondWitness, fpFixed)
}

type GenesisOrRecursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID
	EndID   LinkageID
}

func (rp *GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	witness plonk.Witness[FR],
	acceptableFp FingerPrint,
	genesisFpBytes FingerPrintBytes,
	unitVkeyBytes FingerPrintBytes,
	proof plonk.Proof[FR, G1El, G2El],
	field *big.Int) error {

	// see README / Soundness Diagram for detailed security analysis
	// 1. ensure that vkey.FingerPrint matches either the hardcoded Genesis VKey Fp, or the acceptableFp
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	vkeyFp, err := FpValueOf(api, fp, acceptableFp.BitsPerVar)
	if err != nil {
		return err
	}

	recursiveFpTest := vkeyFp.IsEqual(api, acceptableFp)
	api.Println(recursiveFpTest)

	genesisVkeyFp := FingerPrintFromBytes(genesisFpBytes, acceptableFp.BitsPerVar)
	genesisFpTest := vkeyFp.IsEqual(api, genesisVkeyFp)
	api.Println(genesisFpTest)

	firstVkeyTest := api.Or(recursiveFpTest, genesisFpTest)
	api.Println(firstVkeyTest)
	api.AssertIsEqual(firstVkeyTest, 1)

	// 2. ensure that we have been using the same acceptableFp value, that is, constraint witness against acceptableFp
	nbFpVars := len(acceptableFp.Vals)
	AssertFpWitness(api, acceptableFp, witness.Public[:nbFpVars])

	// 3. constraint witness against BeginID & EndID
	nbIdVars := len(rp.BeginID.Vals)
	AssertIDWitness[FR](api, rp.BeginID, witness.Public[nbFpVars:nbFpVars+nbIdVars])
	AssertIDWitness[FR](api, rp.EndID, witness.Public[nbFpVars+nbIdVars:])

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
