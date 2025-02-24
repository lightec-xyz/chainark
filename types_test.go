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

type byteArrayValueOfCircuitWithSpecifiedLen struct {
	In       frontend.Variable
	Expected []uints.U8
}

func (c *byteArrayValueOfCircuitWithSpecifiedLen) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	res := byteArrayValueOf(api, uapi, c.In, 3)
	api.AssertIsEqual(len(res), len(c.Expected))
	for i := 0; i < len(res); i++ {
		uapi.ByteAssertEq(res[i], c.Expected[i])
	}

	return nil
}

func TestByteArrayValueOfWithSpecifiedLen(t *testing.T) {
	assert := test.NewAssert(t)
	a, b, c := 13, 17, 19
	p := a + (b << 8) + (c << 16)
	expected := uints.NewU8Array([]uint8{uint8(a), uint8(b), uint8(c)})

	circuit := &byteArrayValueOfCircuitWithSpecifiedLen{
		Expected: expected,
	}
	assignment := &byteArrayValueOfCircuitWithSpecifiedLen{
		In:       frontend.Variable(p),
		Expected: expected,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type byteArrayValueOfCircuitWithoutSpecifiedLen struct {
	In       frontend.Variable
	Expected []uints.U8
}

func (c *byteArrayValueOfCircuitWithoutSpecifiedLen) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	res := byteArrayValueOf(api, uapi, c.In)
	for i := 0; i < len(c.Expected); i++ {
		uapi.ByteAssertEq(res[i], c.Expected[i])
	}
	for i := len(c.Expected); i < len(res); i++ {
		uapi.ByteAssertEq(res[i], uints.NewU8(0))
	}

	return nil
}

func TestByteArrayValueOfWithoutSpecifiedLen(t *testing.T) {
	assert := test.NewAssert(t)
	a, b, c := 13, 17, 19
	p := a + (b << 8) + (c << 16)
	expected := uints.NewU8Array([]uint8{uint8(a), uint8(b), uint8(c)})

	circuit := &byteArrayValueOfCircuitWithoutSpecifiedLen{
		Expected: expected,
	}
	assignment := &byteArrayValueOfCircuitWithoutSpecifiedLen{
		In:       frontend.Variable(p),
		Expected: expected,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
