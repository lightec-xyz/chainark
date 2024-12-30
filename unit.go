package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	common_utils "github.com/lightec-xyz/common/utils"
)

type Unit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID          LinkageID                  `gnark:",public"`
	EndID            LinkageID                  `gnark:",public"`
	PlaceHolderFps   []common_utils.FingerPrint `gnark:",public"` // so that Unit could share the same witness alignment with Recursive
	NbPlaceHolderFps int
}

func (*Unit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return nil
}

func NewUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal, nbPlaceHolderFps int,
) *Unit[FR, G1El, G2El, GtEl] {

	holders := make([]common_utils.FingerPrint, nbPlaceHolderFps)
	for i := 0; i < nbPlaceHolderFps; i++ {
		holders[i] = common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal)
	}

	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:        PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:          PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		PlaceHolderFps: holders,
	}
}

func NewUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
	nbHolders int,
) *Unit[FR, G1El, G2El, GtEl] {
	holders := make([]common_utils.FingerPrint, nbHolders)
	for i := 0; i < nbHolders; i++ {
		holders[i] = common_utils.FingerPrintFromBytes(getPlaceholderFp(), bitsPerFpVal)
	}
	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:        LinkageIDFromBytes(beginId, bitsPerIdVal),
		EndID:          LinkageIDFromBytes(endId, bitsPerIdVal),
		PlaceHolderFps: holders,
	}
}

func getPlaceholderFp() common_utils.FingerPrintBytes {
	fp := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fp[i] = byte(i)
	}
	return common_utils.FingerPrintBytes(fp)
}

type UnitCore[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] interface {
	Define(api frontend.API) error
	GetBeginID() LinkageID
	GetEndID() LinkageID
}
