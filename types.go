package chainark

import (
	"slices"

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
	return areVarsEquals(api, id.Vals, other.Vals)
}
func (id LinkageID) ToBytes(api frontend.API) ([]uints.U8, error) {
	vals := make([]frontend.Variable, len(id.Vals))
	copy(vals, id.Vals)
	slices.Reverse[[]frontend.Variable](vals)

	return ValsToU8s(api, vals, id.BitsPerVar)
}

// little-endian here
func LinkageIDFromU8s(api frontend.API, data []uints.U8, bitsPerVar int) LinkageID {
	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		bs := api.ToBinary(data[i].Val, 8)
		copy(bits[i*8:(i+1)*8], bs)
	}

	vals := bitsToVars(api, bits, bitsPerVar)

	return LinkageID{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}
}
func LinkageIDFromBytes(data LinkageIDBytes, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       ValsFromBytes(data, bitsPerVar),
		BitsPerVar: bitsPerVar,
	}
}

func areVarsEquals(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	api.AssertIsEqual(len(a), len(b))
	sum := frontend.Variable(1)
	for i := 0; i < len(a); i++ {
		d := api.Sub(a[i], b[i])
		t := api.IsZero(d)
		sum = api.And(sum, t)
	}

	return sum
}

func bitsToVars(api frontend.API, bits []frontend.Variable, bitsPerVar int) []frontend.Variable {

	vals := make([]frontend.Variable, 0)
	for i := 0; i < len(bits); i += bitsPerVar {
		val := api.FromBinary(bits[i : i+bitsPerVar]...)
		vals = append(vals, val)
	}

	slices.Reverse[[]frontend.Variable](vals)
	return vals
}

func ValsToU8s(api frontend.API, vals []frontend.Variable, bitsPerVar int) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	bytesPerVar := bitsPerVar / 8
	ret := make([]uints.U8, bytesPerVar*len(vals))
	for i := 0; i < len(vals); i++ {
		bytes := uapi.ByteArrayValueOf(vals[i], bytesPerVar)
		begin := i * bytesPerVar
		end := begin + bytesPerVar
		copy(ret[begin:end], bytes)
	}

	return ret, nil
}

func ValsFromBytes(data []byte, bitsPerVar int) []frontend.Variable {
	bytesPerVar := (bitsPerVar + 7) / 8
	ret := make([]frontend.Variable, 0)
	for i := 0; i < len(data); i += bytesPerVar {
		tmp := make([]byte, bytesPerVar)
		copy(tmp, data[i:i+bytesPerVar])
		slices.Reverse[[]byte](tmp)
		ret = append(ret, tmp)
	}

	slices.Reverse[[]frontend.Variable](ret)
	return ret
}
