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
	AcceptableFirstFp FingerPrint[FR] `gnark:",public"`

	SecondVKey  plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof plonk.Proof[FR, G1El, G2El]

	BeginID LinkageID[FR] `gnark:",public"`
	RelayID LinkageID[FR]
	EndID   LinkageID[FR] `gnark:",public"`

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
	fpFixed := FingerPrintFromBytes[FR](c.UnitVKeyFpBytes, c.AcceptableFirstFp.BitsPerElement)
	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.RelayID,
		EndID:   c.EndID,
	}
	return unit.Assert(api, verifier, c.SecondVKey, c.SecondProof, c.SecondWitness, fpFixed)
}

type GenesisOrRecursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID[FR]
	EndID   LinkageID[FR]
}

func (rp *GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	witness plonk.Witness[FR],
	acceptableFp FingerPrint[FR],
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
	vkeyFp, err := FpValueOf[FR](api, fp, acceptableFp.BitsPerElement)
	if err != nil {
		return err
	}

	recursiveFpTest, err := vkeyFp.IsEqual(api, acceptableFp)
	if err != nil {
		return err
	}
	api.Println(recursiveFpTest)

	genesisVkeyFp := FingerPrintFromBytes[FR](genesisFpBytes, acceptableFp.BitsPerElement)
	genesisFpTest, err := vkeyFp.IsEqual(api, genesisVkeyFp)
	if err != nil {
		return err
	}
	api.Println(genesisFpTest)

	firstVkeyTest := api.Or(recursiveFpTest, genesisFpTest)
	api.Println(firstVkeyTest)
	api.AssertIsEqual(firstVkeyTest, 1)

	// 2. ensure that we have been using the same acceptableFp value, that is, constraint witness against acceptableFp
	nbFpEles := len(acceptableFp.Vals)
	nbFpLimbs := len(acceptableFp.Vals[0].Limbs)
	err = AssertFpWitness[FR](api, acceptableFp, witness.Public[:nbFpEles*nbFpLimbs])
	if err != nil {
		return err
	}

	// 3. constraint witness against BeginID & EndID
	nbIdEles := len(rp.BeginID.Vals)
	nbIdLimbs := len(rp.BeginID.Vals[0].Limbs)
	nbAllEles := nbIdEles * nbIdLimbs
	nbTotal := len(witness.Public)
	err = AssertIDWitness[FR](api, rp.BeginID, witness.Public[nbTotal-nbAllEles*2:nbTotal-nbAllEles])
	if err != nil {
		return err
	}
	err = AssertIDWitness[FR](api, rp.EndID, witness.Public[nbTotal-nbAllEles:nbTotal])
	if err != nil {
		return err
	}

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
