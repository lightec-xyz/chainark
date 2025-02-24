package chainark

import (
	"math"
	"slices"

	common_utils "github.com/lightec-xyz/common/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
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
		copy(bits[(n-1-i)*8:(n-i)*8], bs) // reverse order in bytes
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

func (id LinkageID) ToBytes(api frontend.API) ([]uints.U8, error) {
	vals := make([]frontend.Variable, len(id.Vals))
	copy(vals, id.Vals)
	slices.Reverse[[]frontend.Variable](vals)

	return ValsToU8s(api, vals, id.BitsPerVar)
}

func ValsToU8s(api frontend.API, vals []frontend.Variable, bitsPerVar int) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	bytesPerVar := bitsPerVar / 8
	ret := make([]uints.U8, bytesPerVar*len(vals))
	for i := 0; i < len(vals); i++ {
		bytes := byteArrayValueOf(api, uapi, vals[i], bytesPerVar)
		begin := i * bytesPerVar
		end := begin + bytesPerVar
		copy(ret[begin:end], bytes)
	}

	return ret, nil
}

// Convert any varialbe to bits first then to U8 array
// Note that if expectedLen is shorter than actual value, the converted value is *not*
// equal to the original value!
// TODO optimization
func byteArrayValueOf[T uints.U32 | uints.U64](api frontend.API, bf *uints.BinaryField[T], a frontend.Variable, expectedLen ...int) []uints.U8 {
	var opt bits.BaseConversionOption
	var bs []frontend.Variable
	if len(expectedLen) == 1 {
		opt = bits.WithNbDigits(expectedLen[0] * 8)
		bs = bits.ToBinary(api, a, opt)
	} else {
		bs = bits.ToBinary(api, a)
	}

	lenBits := len(bs)
	lenBytes := int(math.Ceil(float64(lenBits) / 8.0))

	ret := make([]uints.U8, lenBytes)
	for i := 0; i < lenBytes; i++ {
		b := bs[i*8]
		for j := 1; j < 8 && i*8+j < lenBits; j++ {
			v := bs[i*8+j]
			v = api.Mul(v, 1<<j)
			b = api.Add(b, v)
		}
		ret[i] = bf.ByteValueOf(b)
	}

	return ret
}
