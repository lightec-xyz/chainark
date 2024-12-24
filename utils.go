package chainark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
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

func testVKeyInSet[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](
	api frontend.API,
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	validFps []common_utils.FingerPrintBytes, bitsPerFpVar int,
) (frontend.Variable, error) {
	fp, err := vkey.FingerPrint(api)
	if err != nil {
		return 0, err
	}
	return common_utils.TestFpInSet(api, fp, validFps, bitsPerFpVar), nil
}

func assertVkeyInSet[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](
	api frontend.API,
	vkey plonk.VerifyingKey[FR, G1El, G2El],
	validFps []common_utils.FingerPrintBytes, bitsPerFpVar int,
) error {
	ret, err := testVKeyInSet(api, vkey, validFps, bitsPerFpVar)
	if err != nil {
		return err
	}
	api.AssertIsEqual(ret, 1)
	return nil
}
