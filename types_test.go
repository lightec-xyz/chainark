package chainark_test

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/chainark"
)

type idCircuit struct {
	FromBytes chainark.LinkageID[sw_bn254.ScalarField]
	Bytes     []byte
}

func (c *idCircuit) Define(api frontend.API) error {
	fromU8s, err := chainark.LinkageIDFromU8s[sw_bn254.ScalarField](api, uints.NewU8Array(c.Bytes), 128) // from U8s
	if err != nil {
		return err
	}

	err = fromU8s.AssertIsEqual(api, c.FromBytes)
	if err != nil {
		return err
	}

	u8s, err := fromU8s.ToBytes(api) // to U8s
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(u8s[i].Val, c.Bytes[i])
	}

	return err
}

func TestLinkageID(t *testing.T) {
	idHex := "18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f"
	idBytes := make([]byte, 32)
	hex.Decode(idBytes, []byte(idHex))

	circuit := idCircuit{
		FromBytes: chainark.LinkageID[sw_bn254.ScalarField]{
			Vals:           make([]emulated.Element[sw_bn254.ScalarField], 2),
			BitsPerElement: 128,
		},
		Bytes: idBytes,
	}
	assert := test.NewAssert(t)
	idFromBytes := chainark.LinkageIDFromBytes[sw_bn254.ScalarField](idBytes, 128) // from bytes
	witness := idCircuit{
		FromBytes: idFromBytes,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
