package common

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/lightec-xyz/chainark"
	"time"
)

func ExtractFp(ccs constraint.ConstraintSystem, vk native_plonk.VerifyingKey, srsDir string) error {
	log := logger.Logger().With().Str("function", "extractFp").Logger()

	srs := kzg.NewSRS(ecc.BN254)
	srsLagrange := kzg.NewSRS(ecc.BN254)

	fpExtractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
	}
	ccsExtractor, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &fpExtractor)
	if err != nil {
		return err
	}
	size := ccsExtractor.GetNbConstraints() + ccsExtractor.GetNbPublicVariables()

	err = ReadSrs(size, srsDir, srs, srsLagrange)
	if err != nil {
		return err
	}

	extractFpStart := time.Now()
	pkExtractor, _, err := native_plonk.Setup(ccsExtractor, srs, srsLagrange)
	if err != nil {
		return err
	}

	recursiveVkey, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	if err != nil {
		return err
	}
	wExt := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursiveVkey,
	}
	witnessExtractor, err := frontend.NewWitness(&wExt, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	_, err = native_plonk.Prove(ccsExtractor, pkExtractor, witnessExtractor)
	if err != nil {
		return err
	}
	log.Debug().Dur("took", time.Since(extractFpStart)).Msg("fp extraction done")

	return nil
}
