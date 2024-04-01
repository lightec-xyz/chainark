package chainark_test

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/chainark"
)

type idCircuit struct {
	FromBytes chainark.LinkageID
	Bytes     []byte
}

func (c *idCircuit) Define(api frontend.API) error {
	fromU8s := chainark.LinkageIDFromU8s(api, uints.NewU8Array(c.Bytes), 128) // from U8s
	fromU8s.AssertIsEqual(api, c.FromBytes)

	t := fromU8s.IsEqual(api, c.FromBytes)
	api.AssertIsEqual(t, 1)

	u8s, err := fromU8s.ToBytes(api) // to U8s
	if err != nil {
		return err
	}
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(u8s[i].Val, c.Bytes[i])
	}

	return nil
}

func TestLinkageID(t *testing.T) {
	idHex := "18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f"
	idBytes := make([]byte, 32)
	hex.Decode(idBytes, []byte(idHex))

	circuit := idCircuit{
		FromBytes: chainark.PlaceholderLinkageID(2, 128),
		Bytes:     idBytes,
	}
	assert := test.NewAssert(t)
	idFromBytes := chainark.LinkageIDFromBytes(idBytes, 128) // from bytes
	witness := idCircuit{
		FromBytes: idFromBytes,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
