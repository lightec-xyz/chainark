package core

import (
	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sha256 "github.com/consensys/gnark/std/hash/sha2"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// note that this file should be implemented by individual application

func GetGenesisIdBytes() []byte {
	genesisIdHex := "843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85"
	genesisIdBytes := make([]byte, 32)
	hex.Decode(genesisIdBytes, []byte(genesisIdHex))
	return genesisIdBytes
}

type UnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID chainark.LinkageID `gnark:",public"`
	EndID   chainark.LinkageID `gnark:",public"`
	NbIDs   frontend.Variable  `gnark:",public"` //exposed to outer circuit
	NbIter  int
	// the rest is application-specific
}

func (c *UnitCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// all application-specific
	api.AssertIsEqual(c.NbIDs, c.NbIter)
	input, err := c.BeginID.ToBytes(api)
	if err != nil {
		return err
	}

	for i := 0; i < c.NbIter; i++ {
		s256, err := sha256.New(api)
		if err != nil {
			return err
		}
		s256.Write(input)
		s256.Write(uints.NewU8Array(([]byte)("chainark example")))
		input = s256.Sum()
	}
	endID := chainark.LinkageIDFromU8s(api, input, common.NbBitsPerIDVal)
	c.EndID.AssertIsEqual(api, endID)
	return nil
}

func NewUnitCircuit(n int) frontend.Circuit {
	return &UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID(common.NbIDVals, common.NbBitsPerIDVal),
		EndID:   chainark.PlaceholderLinkageID(common.NbIDVals, common.NbBitsPerIDVal),
		NbIter:  n,
	}
}

func NewUnitCircuitAssignement(beginID, endID []byte, nbIDs int) frontend.Circuit {
	bID := chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal)
	eID := chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal)

	return &UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: bID,
		EndID:   eID,
		NbIDs:   nbIDs,
	}
}

func NewUnitCcs(n int) constraint.ConstraintSystem {
	unit := NewUnitCircuit(n)
	unitCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, unit)
	if err != nil {
		panic(err)
	}
	return unitCcs
}
