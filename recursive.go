package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
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

	// some constant values passed from outside
	UnitFpBytes    FingerPrintBytes
	GenesisFpBytes FingerPrintBytes
	GenesisIDBytes LinkageIDBytes

	// some data field needs from outside
	innerField  *big.Int
	gOrRCircuit frontend.Circuit
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
	err = gOrR.Assert(api, verifier, c.FirstVKey, c.AcceptableFirstFp, c.GenesisFpBytes, c.GenesisIDBytes, c.FirstProof, c.gOrRCircuit, c.innerField)
	if err != nil {
		return err
	}

	// assert the second proof, including the unit vkey fp assertion
	unit := UnitProof[FR, G1El, G2El, GtEl]{
		BeginID: c.RelayID,
		EndID:   c.EndID,
	}
	return unit.Assert(api, verifier, c.SecondVKey, c.UnitFpBytes, c.SecondProof, c.innerField)
}

type GenesisOrRecursiveCircuitPublicAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] interface {
	New(beginID, endID LinkageID) frontend.Circuit
}

type GenesisOrRecursiveProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID
	EndID   LinkageID
}

func (rp *GenesisOrRecursiveProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	acceptableFp FingerPrint,
	genesisFpBytes FingerPrintBytes,
	genesisIdBytes LinkageIDBytes,
	proof plonk.Proof[FR, G1El, G2El],
	// pubAssignment GenesisOrRecursiveCircuitPublicAssignment[FR, G1El, G2El, GtEl],
	gOrRCircuit frontend.Circuit,
	field *big.Int) error {

	// we only accept the verification key if either holds:
	// 1. that its fingerprint matches the fp of RecursiveCircuit verification key
	// 2. that its fingerprint matches the fp of GenesisCircuit verification key,
	//    AND the begin linkage ID matches the genesis linkage ID
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	vkeyFp, err := FpValueOf(api, fp)
	if err != nil {
		return err
	}
	recursiveFpTest := vkeyFp.IsEqual(api, acceptableFp)

	genesisVkeyFp, err := FpValueOf(api, uints.NewU8Array(genesisFpBytes))
	if err != nil {
		return err
	}
	genesisFpTest := vkeyFp.IsEqual(api, genesisVkeyFp)

	genesisId := LinkageID(uints.NewU8Array(genesisIdBytes))
	genesisIdTest := rp.BeginID.IsEqual(api, &genesisId)
	genesisTest := api.And(genesisFpTest, genesisIdTest)

	firstVkeyTest := api.Or(genesisTest, recursiveFpTest)
	api.AssertIsEqual(firstVkeyTest, 1)

	// assemble the witness and assert the proof
	// assignment := pubAssignment.New(rp.BeginID, rp.EndID)
	witness, err := createWitness[FR](gOrRCircuit, field)
	if err != nil {
		return err
	}
	// TODO do we need to select from RecursiveCircuit and GenesisCircuit? (selector: recursiveFpTest)

	return verifier.AssertProof(vkey, proof, *witness, plonk.WithCompleteArithmetic())
}
