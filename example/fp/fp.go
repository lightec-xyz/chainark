package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/uints"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
)

func main() {
	var unitVkeyFileName string
	if len(os.Args) == 2 {
		unitVkeyFileName = os.Args[1]
	} else {
		unitVkeyFileName = "../unit/unit.vkey"
	}

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

	unit := chainark.UnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BeginID: make([]uints.U8, chainark.IDLength),
		EndID:   make([]uints.U8, chainark.IDLength),
	}
	ccsUnit, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unit)

	extractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsUnit),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &extractor)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)

	var srs, srsLagrange kzg.SRS

	// let's generate the files again
	srs, srsLagrange, err = unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	w := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursiveUnitVkey,
	}
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	_, err = plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

}
