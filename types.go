package chainark

import (
	"slices"

	common_utils "github.com/lightec-xyz/common/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type LinkageID struct {
	Vals       []frontend.Variable
	BitsPerVar int
}
type LinkageIDBytes []byte

func NewLinkageID(v []frontend.Variable, b int) LinkageID {
	return LinkageID{
		Vals:       v,
		BitsPerVar: b,
	}
}
func PlaceholderLinkageID(nbEles, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       make([]frontend.Variable, nbEles),
		BitsPerVar: bitsPerVar,
	}
}
func (id LinkageID) AssertIsEqual(api frontend.API, other LinkageID) {
	api.AssertIsEqual(id.BitsPerVar, other.BitsPerVar)
	api.AssertIsEqual(len(id.Vals), len(other.Vals))
	for i := 0; i < len(id.Vals); i++ {
		api.AssertIsEqual(id.Vals[i], other.Vals[i])
	}
}
func (id LinkageID) IsEqual(api frontend.API, other LinkageID) frontend.Variable {
	api.AssertIsEqual(id.BitsPerVar, other.BitsPerVar)
	return common_utils.AreVarsEquals(api, id.Vals, other.Vals)
}
func (id LinkageID) ToBytes(api frontend.API) ([]uints.U8, error) {
	vals := make([]frontend.Variable, len(id.Vals))
	copy(vals, id.Vals)
	slices.Reverse[[]frontend.Variable](vals)

	return common_utils.ValsToU8s(api, vals, id.BitsPerVar)
}

// little-endian here
func LinkageIDFromU8s(api frontend.API, data []uints.U8, bitsPerVar int) LinkageID {
	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		bs := api.ToBinary(data[i].Val, 8)
		copy(bits[i*8:(i+1)*8], bs)
	}

	vals := common_utils.BitsToVars(api, bits, bitsPerVar)

	return LinkageID{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}
}
func LinkageIDFromBytes(data LinkageIDBytes, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       common_utils.ValsFromBytes(data, bitsPerVar),
		BitsPerVar: bitsPerVar,
	}
}
