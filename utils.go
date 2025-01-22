package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	common_utils "github.com/lightec-xyz/common/utils"
)

func AssertIDWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	common_utils.AssertValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}

func TestIDWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	return common_utils.TestValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}

func assertIds[FR emulated.FieldParams](
	api frontend.API,
	beginId, endId LinkageID,
	witness plonk.Witness[FR],
) {
	nbVars := len(beginId.Vals)
	AssertIDWitness(api, beginId, witness.Public[:nbVars], uint(beginId.BitsPerVar))
	AssertIDWitness(api, endId, witness.Public[nbVars:nbVars*2], uint(endId.BitsPerVar))
}

func GetPlaceholderFp() common_utils.FingerPrintBytes {
	fp := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fp[i] = byte(i)
	}
	return common_utils.FingerPrintBytes(fp)
}
