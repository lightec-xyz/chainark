package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	common_utils "github.com/lightec-xyz/common/utils"
)

func AssertIDWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	common_utils.AssertValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}

func IsIDEqualToWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	return common_utils.TestValsVSWtnsElements[FR](api, id.Vals, witnessValues, nbMaxBitsPerVar...)
}
