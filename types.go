package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"

	common_utils "github.com/lightec-xyz/common/utils"
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
		bs := api.ToBinary(data[n-1-i].Val, 8) // reverse order in u8s
		copy(bits[i*8:(i+1)*8], bs)
	}

	vals := make([]frontend.Variable, 0)
	for i := len(bits); i > 0; i -= bitsPerVar { // reverse order in vars
		val := api.FromBinary(bits[i-bitsPerVar : i]...)
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
		bs := api.ToBinary(id.Vals[n-1-i], id.BitsPerVar) // reverse order in vars
		copy(bits[i*id.BitsPerVar:(i+1)*id.BitsPerVar], bs)
	}

	ret := make([]uints.U8, 0)
	for i := len(bits); i > 0; i -= 8 { // reverse order in u8s
		u8 := api.FromBinary(bits[i-8 : i]...)
		ret = append(ret, uints.U8{Val: u8})
	}

	return ret
}
