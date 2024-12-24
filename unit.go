package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	common_utils "github.com/lightec-xyz/common/utils"
)

type Unit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID      LinkageID                `gnark:",public"`
	EndID        LinkageID                `gnark:",public"`
	placeHoderFp common_utils.FingerPrint `gnark:",public"` // a place holder so that Unit could share the same witness alignment with Recursive
}

func (*Unit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return nil
}

func NewUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
) (frontend.Circuit, error) {
	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:      PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:        PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		placeHoderFp: common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),
	}, nil
}

func NewUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
) (frontend.Circuit, error) {
	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:      LinkageIDFromBytes(beginId, bitsPerIdVal),
		EndID:        LinkageIDFromBytes(endId, bitsPerIdVal),
		placeHoderFp: common_utils.FingerPrintFromBytes(getPlaceholderFp(), bitsPerFpVal),
	}, nil
}

func getPlaceholderFp() common_utils.FingerPrintBytes {
	fp := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fp[i] = byte(i)
	}
	return common_utils.FingerPrintBytes(fp)
}
