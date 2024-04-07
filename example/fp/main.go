package main

import (
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/chainark/example"
)

func main() {
	if len(os.Args) < 2 {
		panic("wrong command")
	}
	fpOption := os.Args[1]

	var unitFp, genesisFp []byte
	var recursiveVk recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	var ccs constraint.ConstraintSystem
	ccsUnit := example.NewUnitCcs()

	if strings.EqualFold(fpOption, "genesis") {
		recursiveVk = example.LoadGenesisVkey()

		if len(os.Args) < 3 {
			panic("wrong command")
		}

		unitFp = example.GetFpBytes(os.Args[2])
		ccs = example.NewGenesisCcs(ccsUnit, unitFp)
	} else if strings.EqualFold(fpOption, "recursive") {
		recursiveVk = example.LoadRecursiveVkey()

		if len(os.Args) < 4 {
			panic("wrong command")
		}
		unitFp = example.GetFpBytes(os.Args[2])
		genesisFp = example.GetFpBytes(os.Args[3])
		ccsGenesis := example.NewGenesisCcs(ccsUnit, unitFp)
		ccs = example.NewRecursiveCcs(ccsUnit, ccsGenesis, unitFp, genesisFp)
	} else {
		recursiveVk = example.LoadUnitVkey()
		ccs = ccsUnit
	}

	extractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &extractor)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)

	var srs, srsLagrange kzg.SRS

	// the files should be there, generated during circuit setup
	srs, srsLagrange, err = unsafekzg.NewSRS(scs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	w := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursiveVk,
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
