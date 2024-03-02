package chainark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type UnitCircuitPublicAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] interface {
	New(currentID, nextID LinkedID[FR, G1El, G2El, GtEl]) (frontend.Circuit, error)
}

type UnitProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	CurrentID LinkedID[FR, G1El, G2El, GtEl]
	NextID    LinkedID[FR, G1El, G2El, GtEl]
}

func (up *UnitProof[FR, G1El, G2El, GtEl]) Assert(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	unitFpBytes FingerPrintBytes,
	proof plonk.Proof[FR, G1El, G2El],
	unitAssignment UnitCircuitPublicAssignment[FR, G1El, G2El, GtEl],
	field *big.Int) error {

	unitFpTest, err := TestVkeyFp[FR, G1El, G2El, GtEl](api, vkey, uints.NewU8Array(unitFpBytes))
	if err != nil {
		return err
	}
	api.AssertIsEqual(unitFpTest, 1)

	assignment, err := unitAssignment.New(up.CurrentID, up.NextID)
	witness, err := createWitness[FR](assignment, field)
	if err != nil {
		return err
	}

	return verifier.AssertProof(vkey, proof, *witness, plonk.WithCompleteArithmetic())
}
