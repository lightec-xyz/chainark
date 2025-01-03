package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	common_utils "github.com/lightec-xyz/common/utils"
)

type MultiUnit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID          LinkageID                  `gnark:",public"`
	EndID            LinkageID                  `gnark:",public"`
	PlaceHolderFps   []common_utils.FingerPrint `gnark:",public"` // so that Unit could share the same witness alignment with Recursive
	NbPlaceHolderFps int
}

func (c *MultiUnit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return nil
}

func NewMultiUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal, nbPlaceHolderFps int,
) *MultiUnit[FR, G1El, G2El, GtEl] {

	holders := make([]common_utils.FingerPrint, nbPlaceHolderFps)
	for i := 0; i < nbPlaceHolderFps; i++ {
		holders[i] = common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal)
	}

	return &MultiUnit[FR, G1El, G2El, GtEl]{
		BeginID:        PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:          PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		PlaceHolderFps: holders,
	}
}

func NewMultiUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
	nbHolders int,
) *MultiUnit[FR, G1El, G2El, GtEl] {
	holders := make([]common_utils.FingerPrint, nbHolders)
	for i := 0; i < nbHolders; i++ {
		holders[i] = common_utils.FingerPrintFromBytes(GetPlaceholderFp(), bitsPerFpVal)
	}
	return &MultiUnit[FR, G1El, G2El, GtEl]{
		BeginID:        LinkageIDFromBytes(beginId, bitsPerIdVal),
		EndID:          LinkageIDFromBytes(endId, bitsPerIdVal),
		PlaceHolderFps: holders,
	}
}

type Unit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	*MultiUnit[FR, G1El, G2El, GtEl]
}

func (c *Unit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return c.MultiUnit.Define(api)
}

func NewUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
) *Unit[FR, G1El, G2El, GtEl] {
	return &Unit[FR, G1El, G2El, GtEl]{
		MultiUnit: NewMultiUnitCircuit[FR, G1El, G2El, GtEl](nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal, 1),
	}
}

func NewUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
) *Unit[FR, G1El, G2El, GtEl] {
	return &Unit[FR, G1El, G2El, GtEl]{
		MultiUnit: NewMultiUnitAssignment[FR, G1El, G2El, GtEl](beginId, endId, bitsPerIdVal, bitsPerFpVal, 1),
	}
}

type UnitCore[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] interface {
	Define(api frontend.API) error
	GetBeginID() LinkageID
	GetEndID() LinkageID
}
