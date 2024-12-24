package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

type unitProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID `gnark:",public"`
	EndID   LinkageID `gnark:",public"`
}

func (up *unitProof[FR, G1El, G2El, GtEl]) assertRelations(
	api frontend.API,
	verifier *plonk.Verifier[FR, G1El, G2El, GtEl],
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	proof plonk.Proof[FR, G1El, G2El],
	witness plonk.Witness[FR],
	validFps []common_utils.FingerPrintBytes, bitsPerFpVar int,
) error {

	// ensure that we are using the correct verification key
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return err
	}
	common_utils.AssertFpInSet(api, fp, validFps, bitsPerFpVar)

	// constraint witness against BeginID & EndID
	nbVars := len(up.BeginID.Vals)
	AssertIDWitness(api, up.BeginID, witness.Public[:nbVars], uint(up.BeginID.BitsPerVar))
	AssertIDWitness(api, up.EndID, witness.Public[nbVars:nbVars*2], uint(up.EndID.BitsPerVar))

	return verifier.AssertProof(vkey, proof, witness, plonk.WithCompleteArithmetic())
}

type Unit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	*unitProof[FR, G1El, G2El, GtEl]
	placeHoderFp common_utils.FingerPrint `gnark:",public"` // a place holder so that Unit could share the same witness alignment with Recursive
}

func (*Unit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return nil
}

func NewUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
) (frontend.Circuit, error) {
	return &Unit[FR, G1El, G2El, GtEl]{
		&unitProof[FR, G1El, G2El, GtEl]{
			BeginID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
			EndID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		},
		common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),
	}, nil
}

func NewUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
) (frontend.Circuit, error) {
	return &Unit[FR, G1El, G2El, GtEl]{
		&unitProof[FR, G1El, G2El, GtEl]{
			BeginID: LinkageIDFromBytes(beginId, bitsPerIdVal),
			EndID:   LinkageIDFromBytes(endId, bitsPerIdVal),
		},
		common_utils.FingerPrintFromBytes(getPlaceholderFp(), bitsPerFpVal),
	}, nil
}

func getPlaceholderFp() common_utils.FingerPrintBytes {
	fp := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fp[i] = byte(i)
	}
	return common_utils.FingerPrintBytes(fp)
}
