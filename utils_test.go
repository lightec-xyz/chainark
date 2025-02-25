package chainark

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type idTestCircuit struct {
	Id LinkageID
	id []byte
}

func (c *idTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Id.Vals[0], c.id[:16])
	api.AssertIsEqual(c.Id.Vals[1], c.id[16:])

	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}

	idEles := [2]emulated.Element[emparams.BN254Fr]{
		newElement(field, api, c.id[:16]),
		newElement(field, api, c.id[16:]),
	}

	AssertIDWitness[sw_bn254.ScalarField](api, c.Id, idEles[:], 128)

	id := RetrieveIDFromElements(api, idEles[:], 128)
	id.AssertIsEqual(api, c.Id)

	return nil
}

func newElement(field *emulated.Field[emparams.BN254Fr], api frontend.API, v []byte) emulated.Element[emparams.BN254Fr] {
	bits := api.ToBinary(v)
	rs := field.FromBits(bits...)
	return *rs
}

func TestIdVSWitness(t *testing.T) {
	assert := test.NewAssert(t)

	idBytes, err := hex.DecodeString("18c4c25dc847bbc76fd3ca67fc4c2028dee5263fddcf01de3faddc20f0462d8f")
	assert.NoError(err)

	circuit := &idTestCircuit{
		Id: PlaceholderLinkageID(2, 128),
		id: idBytes,
	}

	assignment := &idTestCircuit{
		Id: LinkageIDFromBytes(idBytes, 128), // from bytes
	}

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
