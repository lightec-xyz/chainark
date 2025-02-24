package chainark

import (
	common_utils "github.com/lightec-xyz/common/utils"

	"github.com/consensys/gnark/frontend"
	// "github.com/consensys/gnark/std/math/bits"

	"github.com/consensys/gnark/std/math/uints"
)

type LinkageID struct {
	Vals       []frontend.Variable
	BitsPerVar int
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
	if id.BitsPerVar != other.BitsPerVar {
		panic("BitsPerVar not equal")
	}
	return common_utils.AreVarsEquals(api, id.Vals, other.Vals)
}

type LinkageIDBytes []byte

func LinkageIDFromBytes(data LinkageIDBytes, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       common_utils.ValsFromBytes(data, bitsPerVar),
		BitsPerVar: bitsPerVar,
	}
}

func LinkageIDFromU8s(api frontend.API, data []uints.U8, bitsPerVar int) LinkageID {
	n := len(data)
	bits := make([]frontend.Variable, n*8)

	for i := 0; i < n; i++ {
		bs := api.ToBinary(data[i].Val, 8)
		copy(bits[(n-1-i)*8:(n-i)*8], bs) // reverse order in u8s
	}

	vals := make([]frontend.Variable, 0)
	for i := len(bits); i > 0; i -= bitsPerVar {
		val := api.FromBinary(bits[i-bitsPerVar : i]...) // reverse order in vars
		vals = append(vals, val)
	}

	return LinkageID{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}
}

func (id LinkageID) ToU8s(api frontend.API) []uints.U8 {
	n := len(id.Vals)
	bits := make([]frontend.Variable, n*id.BitsPerVar)
	for i := 0; i < n; i++ {
		bs := api.ToBinary(id.Vals[i], id.BitsPerVar)
		copy(bits[(n-1-i)*id.BitsPerVar:(n-i)*id.BitsPerVar], bs) // reverse order in vars
	}

	ret := make([]uints.U8, 0)
	for i := len(bits); i > 0; i -= 8 {
		u8 := api.FromBinary(bits[i-8 : i]...) // reverse order in u8s
		ret = append(ret, uints.U8{Val: u8})
	}

	return ret
}
