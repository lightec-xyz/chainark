package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type LinkageID []uints.U8

func (id *LinkageID) IsEqual(api frontend.API, other *LinkageID) frontend.Variable {
	return testU8ArrayEquality(api, *id, *other)
}

type LinkageIDBytes []byte

type FingerPrint []uints.U8

func (fp FingerPrint) IsEqual(api frontend.API, other FingerPrint) frontend.Variable {
	return testU8ArrayEquality(api, fp, other)
}

func FpValueOf(api frontend.API, v frontend.Variable) (FingerPrint, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	return uapi.ByteArrayValueOf(v), nil
}

type FingerPrintBytes []byte

func TestVkeyFp[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	api frontend.API, vkey plonk.VerifyingKey[FR, G1El, G2El], otherFp FingerPrint) (frontend.Variable, error) {

	fpVar, err := vkey.FingerPrint(api)
	if err != nil {
		return 0, err
	}
	fp, err := FpValueOf(api, fpVar)
	if err != nil {
		return 0, err
	}
	return fp.IsEqual(api, otherFp), nil
}
