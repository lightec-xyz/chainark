package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	common_utils "github.com/lightec-xyz/common/utils"
)

type Unit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID       LinkageID                `gnark:",public"`
	EndID         LinkageID                `gnark:",public"`
	PlaceHolderFp common_utils.FingerPrint `gnark:",public"` // so that Unit could share the same witness alignment with Recursive
}

func (*Unit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return nil
}

func NewUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
) *Unit[FR, G1El, G2El, GtEl] {
	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:       PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:         PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		PlaceHolderFp: common_utils.PlaceholderFingerPrint(nbFpVals, bitsPerFpVal),
	}
}

func NewUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
) *Unit[FR, G1El, G2El, GtEl] {
	return &Unit[FR, G1El, G2El, GtEl]{
		BeginID:       LinkageIDFromBytes(beginId, bitsPerIdVal),
		EndID:         LinkageIDFromBytes(endId, bitsPerIdVal),
		PlaceHolderFp: common_utils.FingerPrintFromBytes(getPlaceholderFp(), bitsPerFpVal),
	}
}

func getPlaceholderFp() common_utils.FingerPrintBytes {
	fp := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fp[i] = byte(i)
	}
	return common_utils.FingerPrintBytes(fp)
}

// users are responsible for constraining the BeginID and EndID against Extra
type UnitCore[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID
	EndID   LinkageID
	Extra   frontend.Circuit
}

func (c *UnitCore[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	return c.Extra.Define(api)
}

func NewUnitCoreCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	nbIdVals, bitsPerIdVal, nbFpVals, bitsPerFpVal int,
) *UnitCore[FR, G1El, G2El, GtEl] {
	return &UnitCore[FR, G1El, G2El, GtEl]{
		BeginID: PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
		EndID:   PlaceholderLinkageID(nbIdVals, bitsPerIdVal),
	}
}

func NewUnitCoreAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	beginId, endId LinkageIDBytes, bitsPerIdVal, bitsPerFpVal int,
	extra frontend.Circuit,
) *UnitCore[FR, G1El, G2El, GtEl] {
	return &UnitCore[FR, G1El, G2El, GtEl]{
		BeginID: LinkageIDFromBytes(beginId, bitsPerIdVal),
		EndID:   LinkageIDFromBytes(endId, bitsPerIdVal),
		Extra:   extra,
	}
}
