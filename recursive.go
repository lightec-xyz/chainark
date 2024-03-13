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
	GenesisIDBytes  LinkageIDBytes
	UnitVKeyFpBytes FingerPrintBytes

	// some data field needs from outside
	innerField *big.Int
}

func (c *RecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	// leave to individual recursive verification:
	// genesis circuit: constraint FirstWitness against (BeginID, RelayID)
	// unit circuit: constraint SecondWitness against (RelayID, EndID)

	// assert the first proof
	gOrR := GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]{
		BeginID: c.BeginID,
		EndID:   c.RelayID,
	}
	err = gOrR.Assert(api, verifier, c.FirstVKey, c.FirstWitness, c.AcceptableFirstFp, c.GenesisFpBytes,
		c.GenesisIDBytes, c.UnitVKeyFpBytes, c.FirstProof, c.innerField)
	if err != nil {
		return err
	}

	// assert the second proof.
	fpFixed := FingerPrintFromBytes[FR](c.UnitVKeyFpBytes, c.AcceptableFirstFp.BitsPerElement)
	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.RelayID,
		EndID:   c.EndID,
	}
	return unit.Assert(api, verifier, c.SecondVKey, c.SecondProof, c.SecondWitness, fpFixed, c.innerField)
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
	genesisIdBytes LinkageIDBytes,
	unitVkeyBytes FingerPrintBytes,
	proof plonk.Proof[FR, G1El, G2El],
	field *big.Int) error {

	// we only accept the verification key if either holds:
	// 1. that its fingerprint matches the fp of RecursiveCircuit verification key
	// 2. that its fingerprint matches the fp of GenesisCircuit verification key,
	//    AND the begin linkage ID matches the genesis linkage ID
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

	genesisId := LinkageIDFromBytes[FR](genesisIdBytes, rp.BeginID.BitsPerElement)
	genesisIdTest, err := rp.BeginID.IsEqual(api, genesisId)
	if err != nil {
		return err
	}
	genesisTest := api.And(genesisFpTest, genesisIdTest)
	api.Println(genesisTest)

	firstVkeyTest := api.Or(genesisTest, recursiveFpTest)
	api.Println(firstVkeyTest)
	api.AssertIsEqual(firstVkeyTest, 1)

	// TODO constraint witness against rp.BeginID and rp.EndId

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}
