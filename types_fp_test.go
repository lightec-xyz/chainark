package chainark_test

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/chainark"
)

type fpCircuit struct {
	FromBytes chainark.FingerPrint
	Bytes     []byte
}

func (c *fpCircuit) Define(api frontend.API) error {
	fromBytes := chainark.FingerPrintFromBytes(c.Bytes, 254) // from U8s
	fromBytes.AssertIsEqual(api, c.FromBytes)

	t := fromBytes.IsEqual(api, c.FromBytes)
	api.AssertIsEqual(t, 1)

	return nil
}

func TestFp(t *testing.T) {
	fpHex := "18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f"
	idBytes := make([]byte, 32)
	hex.Decode(idBytes, []byte(fpHex))

	circuit := fpCircuit{
		FromBytes: chainark.PlaceholderFingerPrint(1, 254),
		Bytes:     idBytes,
	}
	assert := test.NewAssert(t)
	fpFromBytes := chainark.FingerPrintFromBytes(idBytes, 254) // from bytes
	witness := fpCircuit{
		FromBytes: fpFromBytes,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
