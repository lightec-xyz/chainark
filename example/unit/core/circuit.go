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
	"github.com/consensys/gnark/std/math/uints"
)

// note that this file should be implemented by individual application

func GetGenesisIdBytes() []byte {
	genesisIdHex := "843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85"
	genesisIdBytes := make([]byte, 32)
	hex.Decode(genesisIdBytes, []byte(genesisIdHex))
	return genesisIdBytes
}

type UnitCircuit struct {
	ChainarkComp *chainark.Unit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	nbIter       int
}

func (c *UnitCircuit) Define(api frontend.API) error {
	err := c.ChainarkComp.Define(api) // the current implementation just returns nil, but keep the calls here
	if err != nil {
		return err
	}

	value, err := c.ChainarkComp.BeginID.ToBytes(api)
	if err != nil {
		return err
	}

	for i := 0; i < c.nbIter; i++ {
		s256, err := sha256.New(api)
		if err != nil {
			return err
		}
		s256.Write(value)
		s256.Write(uints.NewU8Array(([]byte)("chainark example")))
		value = s256.Sum()
	}
	endID := chainark.LinkageIDFromU8s(api, value, common.NbBitsPerIDVal)
	c.ChainarkComp.EndID.AssertIsEqual(api, endID)
	return nil
}

func NewUnitCircuit(n int) *UnitCircuit {
	unit, err := chainark.NewUnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		common.NbIDVals, common.NbBitsPerIDVal, common.NbFpVals, common.NbBitsPerFpVal)
	if err != nil {
		panic(err)
	}

	return &UnitCircuit{
		ChainarkComp: unit,
		nbIter:       n,
	}
}

func NewUnitCircuitAssignement(beginID, endID []byte, nbIDs int) *UnitCircuit {
	unit, err := chainark.NewUnitAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		beginID, endID, common.NbBitsPerIDVal, common.NbBitsPerFpVal)
	if err != nil {
		panic(err)
	}

	return &UnitCircuit{
		ChainarkComp: unit,
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
