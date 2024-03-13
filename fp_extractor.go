package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

type FpExtractor[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	Vkey recursive_plonk.VerifyingKey[FR, G1El, G2El]
}

func (fe *FpExtractor[FR, G1El, G2El]) Define(api frontend.API) error {
	fp, err := fe.Vkey.FingerPrint(api)
	if err != nil {
		return err
	}

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	fpBytes := uapi.ByteArrayValueOf(fp)
	api.Println("the finger print value is:\n", fpBytes)
	for i := 0; i < len(fpBytes); i++ {
		api.Println("fp[", i, "] = ", fpBytes[i].Val)
	}

	return nil
}
