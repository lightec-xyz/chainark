package chainark

import (
	sha256 "github.com/consensys/gnark/std/hash/sha2"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// note that this file should be implemented by individual application

const IDLength = 32
const UnitPkeyFile = "unit.pkey"
const UnitVkeyFile = "unit.vkey"
const UnitProofFile = "unit.proof"

const FpLength = 32
const GenesisPkeyFile = "genesis.pkey"
const GenesisVkeyFile = "genesis.vkey"
const GenesisProofFile = "genesis.proof"

type UnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID LinkageID `gnark:",public"`
	EndID   LinkageID `gnark:",public"`
	// the rest is application-specific
}

func (uc *UnitCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// all application-specific
	s256, err := sha256.New(api)
	if err != nil {
		return err
	}
	s256.Write(uc.BeginID)
	s256.Write(uints.NewU8Array(([]byte)("chainark example")))

	r := (LinkageID)(s256.Sum())

	idTest := uc.EndID.IsEqual(api, &r)
	api.AssertIsEqual(idTest, 1)

	return nil
}
