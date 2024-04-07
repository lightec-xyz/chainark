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

func NewUnitCircuit() frontend.Circuit {
	return &UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID(IDLength, LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID(IDLength, LinkageIDBitsPerElement),
	}
}

func NewUnitCcs() constraint.ConstraintSystem {
	unit := NewUnitCircuit()
	ccsUnit, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, unit)
	if err != nil {
		panic(err)
	}
	return ccsUnit
}

func NewGenesisCcs(
	ccsUnit constraint.ConstraintSystem,
	unitFp chainark.FingerPrintBytes,
) constraint.ConstraintSystem {
	genesis := chainark.NewGenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		IDLength, LinkageIDBitsPerElement, FpLength, FingerPrintBitsPerElement,
		ccsUnit, unitFp)

	ccsGenesis, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, genesis)
	if err != nil {
		panic(err)
	}

	return ccsGenesis
}

func NewRecursiveCcs(
	ccsUnit constraint.ConstraintSystem,
	ccsGenesis constraint.ConstraintSystem,
	unitFp chainark.FingerPrintBytes,
	genesisFp chainark.FingerPrintBytes,
) constraint.ConstraintSystem {
	recursive := chainark.NewRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		IDLength, LinkageIDBitsPerElement, FpLength, FingerPrintBitsPerElement,
		ccsUnit, ccsGenesis, unitFp, genesisFp)
	ccsRecursive, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, recursive)
	if err != nil {
		panic(err)
	}
	return ccsRecursive
}

func LoadUnitVkey() recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] {
	fileName := "../unit/unit.vkey"
	return loadVKey(fileName)
}

func LoadGenesisVkey() recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] {
	fileName := "../genesis/genesis.vkey"
	return loadVKey(fileName)
}

func LoadRecursiveVkey() recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] {
	fileName := "../recursive/recursive.vkey"
	return loadVKey(fileName)
}

func loadVKey(file string) recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] {
	unitVkeyFile, err := os.Open(file)
	defer unitVkeyFile.Close()
	if err != nil {
		panic(err)
	}
	unitVkey := plonk.NewVerifyingKey(ecc.BN254)
	unitVkey.ReadFrom(unitVkeyFile)

	recursiveUnitVkey, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unitVkey)
	if err != nil {
		panic(err)
	}

	return recursiveUnitVkey
}

func GetFpBytes(fpHex string) []byte {
	fpBytes := make([]byte, 32)
	hex.Decode(fpBytes, []byte(fpHex))
	return fpBytes
}
