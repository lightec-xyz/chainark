package chainark

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type IDCircuit struct {
	FromBytes LinkageID
	Bytes     []byte
}

func (c *IDCircuit) Define(api frontend.API) error {
	fromU8s := LinkageIDFromU8s(api, uints.NewU8Array(c.Bytes), 128) // from U8s
	fromU8s.AssertIsEqual(api, c.FromBytes)

	t := fromU8s.IsEqual(api, c.FromBytes)
	api.AssertIsEqual(t, 1)

	u8s := fromU8s.ToU8s(api) // to U8s
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(u8s[i].Val, c.Bytes[i])
	}

	return nil
}

func TestLinkageID(t *testing.T) {
	assert := test.NewAssert(t)

	idHex := "18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f"
	idBytes, err := hex.DecodeString(idHex)
	assert.NoError(err)

	circuit := IDCircuit{
		FromBytes: PlaceholderLinkageID(2, 128),
		Bytes:     idBytes,
	}
	idFromBytes := LinkageIDFromBytes(idBytes, 128) // from bytes
	witness := IDCircuit{
		FromBytes: idFromBytes,
	}

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
