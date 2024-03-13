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

type LinkageID[FR emulated.FieldParams] struct {
	Vals           []emulated.Element[FR]
	BitsPerElement int
}
type LinkageIDBytes []byte

func NewLinkageID[FR emulated.FieldParams](v []emulated.Element[FR], b int) LinkageID[FR] {
	return LinkageID[FR]{
		Vals:           v,
		BitsPerElement: b,
	}
}
func PlaceholderLinkageID[FR emulated.FieldParams](nbEles, bitsPerElement int) LinkageID[FR] {
	return LinkageID[FR]{
		Vals:           make([]emulated.Element[FR], nbEles),
		BitsPerElement: bitsPerElement,
	}
}
func (id LinkageID[FR]) AssertIsEqual(api frontend.API, other LinkageID[FR]) error {
	api.AssertIsEqual(id.BitsPerElement, other.BitsPerElement)
	return assertElementsEqual[FR](api, id.Vals, other.Vals)
}
func (id LinkageID[FR]) IsEqual(api frontend.API, other LinkageID[FR]) (frontend.Variable, error) {
	api.AssertIsEqual(id.BitsPerElement, other.BitsPerElement)
	return areElementsEqual[FR](api, id.Vals, other.Vals)
}
func (id LinkageID[FR]) ToBytes(api frontend.API) ([]uints.U8, error) {
	return ElementsToU8s(api, id.Vals, id.BitsPerElement)
}

// little-endian here
func LinkageIDFromU8s[FR emulated.FieldParams](api frontend.API, data []uints.U8, bitsPerElement int) (LinkageID[FR], error) {
	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		bs := api.ToBinary(data[i].Val)
		copy(bits[i*8:(i+1)*8], bs)
	}

	vals, err := bitsToElements[FR](api, bits, bitsPerElement)
	if err != nil {
		return LinkageID[FR]{}, err
	}
	return LinkageID[FR]{
		Vals:           vals,
		BitsPerElement: bitsPerElement,
	}, nil
}
func LinkageIDFromBytes[FR emulated.FieldParams](data LinkageIDBytes, bitsPerElement int) LinkageID[FR] {
	return LinkageID[FR]{
		Vals:           ElementsFromBytes[FR](data, bitsPerElement),
		BitsPerElement: bitsPerElement,
	}
}

type FingerPrint[FR emulated.FieldParams] struct {
	Vals           []emulated.Element[FR]
	BitsPerElement int
}

type FingerPrintBytes []byte

func NewFingerPrint[FR emulated.FieldParams](v []emulated.Element[FR], b int) FingerPrint[FR] {
	return FingerPrint[FR]{
		Vals:           v,
		BitsPerElement: b,
	}
}
func PlaceholderFingerPrint[FR emulated.FieldParams](nbEles, bitsPerElement int) FingerPrint[FR] {
	return FingerPrint[FR]{
		Vals:           make([]emulated.Element[FR], nbEles),
		BitsPerElement: bitsPerElement,
	}
}
func (fp FingerPrint[FR]) AssertIsEqual(api frontend.API, other FingerPrint[FR]) error {
	api.AssertIsEqual(fp.BitsPerElement, other.BitsPerElement)
	return assertElementsEqual[FR](api, fp.Vals, other.Vals)
}
func (fp FingerPrint[FR]) IsEqual(api frontend.API, other FingerPrint[FR]) (frontend.Variable, error) {
	api.AssertIsEqual(fp.BitsPerElement, other.BitsPerElement)
	return areElementsEqual[FR](api, fp.Vals, other.Vals)
}

func FpValueOf[FR emulated.FieldParams](api frontend.API, v frontend.Variable, bitsPerElement int) (FingerPrint[FR], error) {
	bits := api.ToBinary(v)

	eles, err := bitsToElements[FR](api, bits, bitsPerElement)
	if err != nil {
		return FingerPrint[FR]{}, err
	}
	return FingerPrint[FR]{
		Vals:           eles,
		BitsPerElement: bitsPerElement,
	}, nil
}

func TestVkeyFp[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	api frontend.API, vkey plonk.VerifyingKey[FR, G1El, G2El], otherFp FingerPrint[FR]) (frontend.Variable, error) {

	fpVar, err := vkey.FingerPrint(api)
	if err != nil {
		return 0, err
	}
	fp, err := FpValueOf[FR](api, fpVar, otherFp.BitsPerElement)
	if err != nil {
		return 0, err
	}
	return fp.IsEqual(api, otherFp)
}

func FingerPrintFromBytes[FR emulated.FieldParams](data FingerPrintBytes, bitsPerElement int) FingerPrint[FR] {
	return FingerPrint[FR]{
		Vals:           ElementsFromBytes[FR](data, bitsPerElement),
		BitsPerElement: bitsPerElement,
	}
}

func assertElementsEqual[FR emulated.FieldParams](api frontend.API, a, b []emulated.Element[FR]) error {
	field, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}

	api.AssertIsEqual(len(a), len(b))
	for i := 0; i < len(a); i++ {
		field.AssertIsEqual(&a[i], &b[i])
	}

	return nil
}

func areElementsEqual[FR emulated.FieldParams](api frontend.API, a, b []emulated.Element[FR]) (frontend.Variable, error) {
	field, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, err
	}

	api.AssertIsEqual(len(a), len(b))
	sum := frontend.Variable(1)
	for i := 0; i < len(a); i++ {
		d := field.Sub(&a[i], &b[i])
		z := field.IsZero(d)
		sum = api.And(sum, z)
	}

	sum = api.Sub(1, sum)

	return api.IsZero(sum), nil
}

func bitsToElements[FR emulated.FieldParams](api frontend.API, bits []frontend.Variable, bitsPerElement int) ([]emulated.Element[FR], error) {
	field, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, err
	}

	len := len(bits)
	r := len % bitsPerElement
	l := (len - r) / bitsPerElement
	ret := make([]emulated.Element[FR], l)
	for i := 0; i < l; i++ {
		v := bits[i*bitsPerElement : (i+1)*bitsPerElement]
		ret[i] = *field.FromBits(v...)
	}

	if r > 0 {
		v := bits[l*bitsPerElement:]
		ret = append(ret, *field.FromBits(v...))
	}

	return ret, nil
}

func ElementsToU8s[FR emulated.FieldParams](api frontend.API, vals []emulated.Element[FR], bitsPerElement int) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	bytesPerElement := bitsPerElement / 8
	ret := make([]uints.U8, bytesPerElement*len(vals))
	var fr FR
	bitsPerLimb := fr.BitsPerLimb()
	nbLimbs := bitsPerElement / int(bitsPerLimb)
	bytesPerLimb := int(bitsPerLimb / 8)
	for i := 0; i < len(vals); i++ {
		for j := 0; j < nbLimbs; j++ {
			bytes := uapi.ByteArrayValueOf(vals[i].Limbs[j], bytesPerLimb)
			begin := i*bytesPerElement + j*bytesPerLimb
			end := begin + bytesPerLimb
			copy(ret[begin:end], bytes)
		}
	}

	return ret, nil
}

func ElementsFromBytes[FR emulated.FieldParams](data []byte, bitsPerElement int) []emulated.Element[FR] {
	bytesPerElement := bitsPerElement / 8

	var fr FR
	bytesPerLimb := fr.BitsPerLimb() / 8
	limbsPerElement := bytesPerElement / int(bytesPerLimb)

	r := len(data) % bytesPerElement
	nbElements := (len(data) - r) / bytesPerElement
	if r > 0 {
		nbElements += 1
	}
	elems := make([]emulated.Element[FR], nbElements)

	for i := 0; i < nbElements; i++ {
		limbs := make([]frontend.Variable, fr.NbLimbs())
		for j := 0; j < limbsPerElement; j++ {
			begin := i*bytesPerElement + j*int(bytesPerLimb)
			end := begin + int(bytesPerLimb)
			if end > len(data) {
				end = len(data)
			}
			d := data[begin:end]

			tmp := make([]byte, len(d))
			copy(tmp, d)
			slices.Reverse[[]byte](tmp)

			bi := big.NewInt(0).SetBytes(tmp)
			limbs[j] = frontend.Variable(bi)
		}
		for j := limbsPerElement; j < int(fr.NbLimbs()); j++ {
			limbs[j] = frontend.Variable(0)
		}
		elems[i] = emulated.Element[FR]{
			Limbs: limbs,
		}
	}

	return elems
}
