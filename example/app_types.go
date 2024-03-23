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

const FingerPrintBitsPerElement = 128
const FpLength = 2

func GetUnitFpBytes() []byte {
	// computed with the fp/fp_unit utility, before computing you need to at least compute the verification key for the unit circuit by running unit --setup
	return []byte{3, 65, 71, 15, 176, 248, 28, 94, 225, 35, 137, 51, 17, 224, 65, 157, 226, 249, 127, 36, 13, 145, 248, 183, 40, 26, 145, 198, 134, 205, 148, 14}
}
func GetGenesisFpBytes() []byte {
	// same, genesis --setup first, then fp_genesis
	return []byte{83, 231, 89, 73, 151, 4, 108, 80, 178, 19, 227, 159, 88, 242, 99, 151, 33, 136, 165, 61, 150, 180, 40, 33, 1, 249, 173, 33, 108, 31, 69, 23}
}
func GetRecursiveFpBytes() []byte {
	// same
	return []byte{6, 161, 195, 134, 137, 249, 20, 22, 55, 85, 34, 193, 75, 42, 188, 85, 5, 72, 198, 117, 236, 138, 3, 108, 206, 11, 131, 123, 236, 178, 169, 42}
}
func GetGenesisIdBytes() []byte {
	genesisIdHex := "843d12c93f9079e0d63a6101c31ac8a7eda3b78d6c4ea5b63fef0bf3eb91aa85"
	genesisIdBytes := make([]byte, 32)
	hex.Decode(genesisIdBytes, []byte(genesisIdHex))
	return genesisIdBytes
}

type UnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginID chainark.LinkageID[FR] `gnark:",public"`
	EndID   chainark.LinkageID[FR] `gnark:",public"`
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

	r, err := chainark.LinkageIDFromU8s[FR](api, s256.Sum(), 128)
	if err != nil {
		return err
	}

	return uc.EndID.AssertIsEqual(api, r)
}

func CreateGenesisObjects() (recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine],
	constraint.ConstraintSystem, constraint.ConstraintSystem) {
	unit := UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](IDLength, LinkageIDBitsPerElement),
		EndID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](IDLength, LinkageIDBitsPerElement),
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

	genesis := chainark.GenesisCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		UnitVKey:          recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		FirstProof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		SecondProof:       recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
		AcceptableFirstFp: chainark.PlaceholderFingerPrint[sw_bn254.ScalarField](FpLength, FingerPrintBitsPerElement),

		GenesisID: chainark.PlaceholderLinkageID[sw_bn254.ScalarField](IDLength, LinkageIDBitsPerElement),
		FirstID:   chainark.PlaceholderLinkageID[sw_bn254.ScalarField](IDLength, LinkageIDBitsPerElement),
		SecondID:  chainark.PlaceholderLinkageID[sw_bn254.ScalarField](IDLength, LinkageIDBitsPerElement),

		FirstWitness:  recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),
		SecondWitness: recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsUnit),

		UnitVkeyFpBytes: GetUnitFpBytes(),
		InnerField:      ecc.BN254.ScalarField(),
	}

	ccsGenesis, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &genesis)
	if err != nil {
		panic(err)
	}
	return recursiveUnitVkey, ccsGenesis, ccsUnit
}
