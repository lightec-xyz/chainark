package chainark

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
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
	return ValsToU8s(api, id.Vals, id.BitsPerVar)
}

// little-endian here
func LinkageIDFromU8s(api frontend.API, data []uints.U8, bitsPerVar int) LinkageID {
	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		bs := api.ToBinary(data[i].Val)
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

type FingerPrint struct {
	Vals       []frontend.Variable
	BitsPerVar int
}

type FingerPrintBytes []byte

func NewFingerPrint(v []frontend.Variable, b int) FingerPrint {
	return FingerPrint{
		Vals:       v,
		BitsPerVar: b,
	}
}
func PlaceholderFingerPrint(nbVars, bitsPerVar int) FingerPrint {
	return FingerPrint{
		Vals:       make([]frontend.Variable, nbVars),
		BitsPerVar: bitsPerVar,
	}
}
func (fp FingerPrint) AssertIsEqual(api frontend.API, other FingerPrint) {
	api.AssertIsEqual(fp.BitsPerVar, other.BitsPerVar)
	api.AssertIsEqual(len(fp.Vals), len(other.Vals))
	for i := 0; i < len(fp.Vals); i++ {
		api.AssertIsEqual(fp.Vals[i], other.Vals[i])
	}
}
func (fp FingerPrint) IsEqual(api frontend.API, other FingerPrint) frontend.Variable {
	api.AssertIsEqual(fp.BitsPerVar, other.BitsPerVar)
	return areVarsEquals(api, fp.Vals, other.Vals)
}

func FpValueOf(api frontend.API, v frontend.Variable, bitsPerVar int) (FingerPrint, error) {
	bits := api.ToBinary(v)

	vals := bitsToVars(api, bits, bitsPerVar)
	return FingerPrint{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}, nil
}

func TestVkeyFp[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	api frontend.API, vkey plonk.VerifyingKey[FR, G1El, G2El], otherFp FingerPrint) (frontend.Variable, error) {

	fpVar, err := vkey.FingerPrint(api)
	if err != nil {
		return 0, err
	}
	fp, err := FpValueOf(api, fpVar, otherFp.BitsPerVar)
	if err != nil {
		return 0, err
	}
	return fp.IsEqual(api, otherFp), nil
}

func FingerPrintFromBytes(data FingerPrintBytes, bitsPerVar int) FingerPrint {
	return FingerPrint{
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
		d := data[i : i+bytesPerVar]
		tmp := make([]byte, len(d))
		copy(tmp, d)
		slices.Reverse[[]byte](tmp)

		bi := big.NewInt(0).SetBytes(tmp)
		ret = append(ret, frontend.Variable(bi))
	}

	return ret
}
