package chainark

import (
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	VKey    plonk.VerifyingKey[FR, G1El, G2El]
	Proof   plonk.Proof[FR, G1El, G2El]
	Witness plonk.Witness[FR]

	// circuit constants
	VkeyFpsBytes []common_utils.FingerPrintBytes
	NbIdVars     int
	NbFpVars     int
	NbSelfFps    int
}

func (c *Verifier[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	if c.NbSelfFps != len(c.VkeyFpsBytes) {
		panic("length mismatch")
	}

	vkeyFp, err := c.VKey.FingerPrint(api)
	if err != nil {
		return err
	}

	vkeyFps := make([]common_utils.FingerPrint[FR], len(c.VkeyFpsBytes))
	for i := 0; i < len(c.VkeyFpsBytes); i++ {
		vkeyFps[i] = common_utils.FingerPrintFromBytes[FR](c.VkeyFpsBytes[i])
	}
	recursiveFpTest := common_utils.TestFpInFpSet[FR](api, vkeyFp, vkeyFps)

	initialOffset := c.NbIdVars * 2
	nbFpVars := c.NbFpVars

	setTest := TestRecursiveFps[FR](api, c.Witness, vkeyFps, initialOffset, nbFpVars, c.NbSelfFps)
	api.AssertIsEqual(recursiveFpTest, setTest)

	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	return verifier.AssertProof(c.VKey, c.Proof, c.Witness, plonk.WithCompleteArithmetic())
}

func NewVerifierCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	ccs constraint.ConstraintSystem,
	vkeyFpsBytes []common_utils.FingerPrintBytes,
	nbIdVars, nbFpVars, nbSelfFps int,
) (*Verifier[FR, G1El, G2El, GtEl], error) {
	if len(vkeyFpsBytes) != nbSelfFps {
		panic("wrong number of nbSelfFps or vkeyFpsBytes")
	}
	return &Verifier[FR, G1El, G2El, GtEl]{
		VKey:    plonk.PlaceholderVerifyingKey[FR, G1El, G2El](ccs),
		Proof:   plonk.PlaceholderProof[FR, G1El, G2El](ccs),
		Witness: plonk.PlaceholderWitness[FR](ccs),

		VkeyFpsBytes: vkeyFpsBytes,
		NbIdVars:     nbIdVars,
		NbFpVars:     nbFpVars,
		NbSelfFps:    nbSelfFps,
	}, nil
}

func NewVerifierAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	vkey native_plonk.VerifyingKey,
	proof native_plonk.Proof,
	witness witness.Witness,
) (*Verifier[FR, G1El, G2El, GtEl], error) {
	vk, err := plonk.ValueOfVerifyingKey[FR, G1El, G2El](vkey)
	if err != nil {
		return nil, err
	}
	pf, err := plonk.ValueOfProof[FR, G1El, G2El](proof)
	if err != nil {
		return nil, err
	}
	wt, err := plonk.ValueOfWitness[FR](witness)
	if err != nil {
		return nil, err
	}

	return &Verifier[FR, G1El, G2El, GtEl]{
		VKey:    vk,
		Proof:   pf,
		Witness: wt,
	}, nil
}
