package example

import (
	"encoding/hex"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sha256 "github.com/consensys/gnark/std/hash/sha2"
	"github.com/lightec-xyz/chainark"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// note that this file should be implemented by individual application

const UnitPkeyFile = "unit.pkey"
const UnitVkeyFile = "unit.vkey"
const UnitProofFile = "unit.proof"

const GenesisPkeyFile = "genesis.pkey"
const GenesisVkeyFile = "genesis.vkey"
const GenesisProofFile = "genesis.proof"

const RecursivePkeyFile = "recursive.pkey"
const RecursiveVkeyFile = "recursive.vkey"
const RecursiveProofFile = "recursive.proof"

const LinkageIDBitsPerElement = 128
const IDLength = 2 // linkage id is sha256, thus 256 bits = 128 * 2

const FingerPrintBitsPerElement = 254
const FpLength = 1

func GetUnitFpBytes() []byte {
	// computed with the fp/fp_unit utility, before computing you need to at least compute the verification key for the unit circuit by running unit --setup
	return []byte{95, 171, 83, 204, 191, 189, 136, 179, 193, 120, 236, 26, 35, 14, 48, 83, 196, 108, 153, 125, 236, 128, 57, 253, 53, 28, 128, 22, 228, 182, 3, 21}
}
func GetGenesisFpBytes() []byte {
	// same, genesis --setup first, then fp_genesis
	return []byte{148, 198, 75, 3, 246, 49, 190, 151, 215, 92, 64, 54, 133, 58, 97, 41, 10, 56, 64, 181, 190, 169, 119, 40, 66, 235, 178, 15, 138, 29, 101, 32}
}
func GetRecursiveFpBytes() []byte {
	// same
	return []byte{205, 156, 166, 80, 194, 0, 128, 62, 76, 133, 44, 179, 147, 123, 93, 94, 65, 10, 151, 143, 143, 16, 82, 66, 200, 80, 183, 133, 92, 50, 176, 8}
}
func GetGenesisIdBytes() []byte {
	genesisIdHex := "843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85"
	genesisIdBytes := make([]byte, 32)
	hex.Decode(genesisIdBytes, []byte(genesisIdHex))
	return genesisIdBytes
}

type UnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID chainark.LinkageID `gnark:",public"`
	EndID   chainark.LinkageID `gnark:",public"`
	// the rest is application-specific
}

func (uc *UnitCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// all application-specific
	s256, err := sha256.New(api)
	if err != nil {
		return err
	}

	beginBytes, err := uc.BeginID.ToBytes(api)
	if err != nil {
		return err
	}
	s256.Write(beginBytes)

	s256.Write(uints.NewU8Array(([]byte)("chainark example")))

	r := chainark.LinkageIDFromU8s(api, s256.Sum(), 128)

	uc.EndID.AssertIsEqual(api, r)
	return nil
}

func CreateGenesisObjects() (recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine],
	constraint.ConstraintSystem, constraint.ConstraintSystem) {
	unit := UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID(IDLength, LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID(IDLength, LinkageIDBitsPerElement),
	}
	ccsUnit, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unit)
	if err != nil {
		panic(err)
	}

	unitVkeyFileName := "../unit/unit.vkey"
	unitVkeyFile, err := os.Open(unitVkeyFileName)
	if err != nil {
		panic(err)
	}
	unitVkey := plonk.NewVerifyingKey(ecc.BN254)
	unitVkey.ReadFrom(unitVkeyFile)
	unitVkeyFile.Close()

	recursiveUnitVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unitVkey)
	if err != nil {
		panic(err)
	}

	genesis := chainark.NewGenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		IDLength, LinkageIDBitsPerElement, FpLength, FingerPrintBitsPerElement,
		ccsUnit, GetUnitFpBytes())

	ccsGenesis, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, genesis)
	if err != nil {
		panic(err)
	}
	return recursiveUnitVkey, ccsGenesis, ccsUnit
}
