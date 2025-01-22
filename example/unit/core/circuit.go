package core

import (
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sha256 "github.com/consensys/gnark/std/hash/sha2"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example/common"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// note that this file should be implemented by individual application

type UnitCircuit struct {
	ChainarkComp *chainark.MultiUnit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	nbIter       int
	extraCost    int
}

func (c *UnitCircuit) Define(api frontend.API) error {

	err := c.ChainarkComp.Define(api) // the current implementation just returns nil, but keep the calls here
	if err != nil {
		return err
	}

	iter := IteratedHash{
		BeginID: c.ChainarkComp.BeginID,
		EndID:   c.ChainarkComp.EndID,
		nbIter:  c.nbIter,
	}
	err = iter.Define(api) // taking a shortcut without treating IteratedHash as a circuit
	if err != nil {
		return err
	}

	for i := 0; i < c.extraCost; i++ {
		s256, err := sha256.New(api)
		if err != nil {
			return err
		}
		s256.Write(uints.NewU8Array(([]byte)("chainark example")))
		s256.Sum()
	}

	return nil
}

func NewUnitCircuit(n int, extra ...int) *UnitCircuit {
	ext := 0
	if len(extra) != 0 {
		ext = extra[0]
	}
	return &UnitCircuit{
		ChainarkComp: chainark.NewMultiUnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
			common.NbIDVals, common.NbBitsPerIDVal, 2),
		nbIter:    n,
		extraCost: ext,
	}
}

func NewUnitAssignement(beginID, endID []byte) *UnitCircuit {
	return &UnitCircuit{
		ChainarkComp: chainark.NewMultiUnitAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
			beginID, endID, common.NbBitsPerIDVal, 2),
	}
}

type IteratedHash struct {
	BeginID chainark.LinkageID
	EndID   chainark.LinkageID
	nbIter  int
}

func (c *IteratedHash) GetBeginID() chainark.LinkageID {
	return c.BeginID
}

func (c *IteratedHash) GetEndID() chainark.LinkageID {
	return c.EndID
}

func (c *IteratedHash) Define(api frontend.API) error {
	value, err := c.BeginID.ToBytes(api)
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
	c.EndID.AssertIsEqual(api, endID)

	return nil
}

func NewIteratedHashCircuit(n int) *IteratedHash {
	return &IteratedHash{
		BeginID: chainark.PlaceholderLinkageID(common.NbIDVals, common.NbBitsPerIDVal),
		EndID:   chainark.PlaceholderLinkageID(common.NbIDVals, common.NbBitsPerIDVal),
		nbIter:  n,
	}
}

func NewIteratedHashAssignement(beginID, endID []byte) *IteratedHash {
	return &IteratedHash{
		BeginID: chainark.LinkageIDFromBytes(beginID, common.NbBitsPerIDVal),
		EndID:   chainark.LinkageIDFromBytes(endID, common.NbBitsPerIDVal),
	}
}
