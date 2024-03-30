package common

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/logger"
	"math/bits"
	"os"
	"path/filepath"
	"time"
)

func ReadSrs(size int, srsDir string, srs kzg.SRS, srsLagrange kzg.SRS) error {
	log := logger.Logger().With().Str("function", "ReadSrs").Logger()
	sizeLagrange := ecc.NextPowerOfTwo(uint64(size))
	index := Power2Index(sizeLagrange)
	srsFile := filepath.Join(srsDir, fmt.Sprintf("bn254_pow_%v.srs", index))
	lagrangeSrsFile := filepath.Join(srsDir, fmt.Sprintf("bn254_pow_%v.lsrs", index))
	log.Debug().Str("srsFile", srsFile).Str("lagrangeSrsFile", lagrangeSrsFile).Msg("read srs")
	fsrs, err := os.Open(srsFile)
	if err != nil {
		return err
	}
	defer fsrs.Close()
	fsrsLagrange, err := os.Open(lagrangeSrsFile)
	if err != nil {
		return err
	}
	defer fsrsLagrange.Close()

	readSRSStart := time.Now()
	_, err = srs.ReadFrom(fsrs)
	if err != nil {
		return err
	}
	if len(srs.(*kzg_bn254.SRS).Pk.G1) != int(sizeLagrange+3) {
		return fmt.Errorf("incorrect srs size")
	}
	log.Debug().Dur("took", time.Since(readSRSStart)).Msg("read srs done")

	readSRSSLagrangeStart := time.Now()
	_, err = srsLagrange.ReadFrom(fsrsLagrange)
	if err != nil {
		return err
	}
	if len(srsLagrange.(*kzg_bn254.SRS).Pk.G1) != int(sizeLagrange) {
		return fmt.Errorf("incorrect srs lagrange size")
	}
	log.Debug().Dur("took", time.Since(readSRSSLagrangeStart)).Msg("read srs lagrange done")
	return nil
}

func ReadCcs(ccsFile string) (constraint.ConstraintSystem, error) {
	log := logger.Logger().With().Str("function", "ReadCcs").Logger()
	readCcsStart := time.Now()
	var ccs cs_bn254.SparseR1CS
	fccs, err := os.Open(ccsFile)
	if err != nil {
		return nil, err
	}
	defer fccs.Close()
	_, err = ccs.ReadFrom(fccs)
	if err != nil {
		return nil, err
	}
	log.Debug().Dur("took", time.Since(readCcsStart)).Str("file", ccsFile).Msg("read ccs done")

	return &ccs, nil
}

func ReadVk(vkFile string) (native_plonk.VerifyingKey, error) {
	log := logger.Logger().With().Str("function", "ReadVk").Logger()
	readVkStart := time.Now()
	var vk plonk_bn254.VerifyingKey
	fvk, err := os.Open(vkFile)
	defer fvk.Close()
	_, err = vk.ReadFrom(fvk)
	if err != nil {
		return nil, err
	}
	log.Debug().Dur("took", time.Since(readVkStart)).Str("file", vkFile).Msg("read vk done")

	return &vk, err
}

func ReadPk(pkFile string) (native_plonk.ProvingKey, error) {
	log := logger.Logger().With().Str("function", "ReadPk").Logger()
	fpk, err := os.Open(pkFile)
	if err != nil {
		return nil, err
	}
	defer fpk.Close()
	var bn254Pk plonk_bn254.ProvingKey
	var pk native_plonk.ProvingKey
	readPkStart := time.Now()
	_, err = bn254Pk.UnsafeReadFrom(fpk)
	if err != nil {
		return nil, err
	}
	readPKDuration := time.Since(readPkStart)
	pk = &bn254Pk
	log.Debug().Dur("took", readPKDuration).Str("file", pkFile).Msg("read pk")
	return pk, nil
}

func ReadWitness(pubWitnessFile string) (witness.Witness, error) {
	field := ecc.BN254.ScalarField()
	var wit witness.Witness
	wit, err := witness.New(field)
	if err != nil {
		return nil, err
	}
	fpubWitness, err := os.Open(pubWitnessFile)
	if err != nil {
		return nil, err
	}
	defer fpubWitness.Close()
	_, err = wit.ReadFrom(fpubWitness)
	if err != nil {
		return nil, err
	}
	return wit, nil
}

func ReadProof(proofFile string) (native_plonk.Proof, error) {
	var bn254Proof plonk_bn254.Proof
	fproof, err := os.Open(proofFile)
	if err != nil {
		return nil, err
	}
	defer fproof.Close()
	_, err = bn254Proof.ReadFrom(fproof)
	if err != nil {
		return nil, err
	}
	return &bn254Proof, nil
}

func WriteProof(proofFilePath string, proof native_plonk.Proof) error {
	exists, err := FileExists(proofFilePath)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(proofFilePath)
		if err != nil {
			return err
		}
	}
	fproof, err := os.Create(proofFilePath)
	if err != nil {
		return err
	}
	defer fproof.Close()
	_, err = proof.WriteTo(fproof)
	if err != nil {
		return err
	}
	return nil
}
func WriteWitness(wtnsFilePath string, wtns witness.Witness) error {
	wtns, err := wtns.Public()
	if err != nil {
		return err
	}
	exists, err := FileExists(wtnsFilePath)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(wtnsFilePath)
		if err != nil {
			return err
		}
	}
	fwtns, err := os.Create(wtnsFilePath)
	if err != nil {
		return err
	}
	defer fwtns.Close()
	_, err = wtns.WriteTo(fwtns)
	if err != nil {
		return err
	}
	return nil
}

func WriteCcs(cssFilePath string, ccs constraint.ConstraintSystem) error {
	exists, err := FileExists(cssFilePath)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(cssFilePath)
		if err != nil {
			return err
		}
	}
	fccs, err := os.Create(cssFilePath)
	if err != nil {
		return err
	}
	defer fccs.Close()
	_, err = ccs.WriteTo(fccs)
	if err != nil {
		return err
	}
	return nil
}
func WritePk(pkFilePath string, pk native_plonk.ProvingKey) error {
	exists, err := FileExists(pkFilePath)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(pkFilePath)
		if err != nil {
			return err
		}
	}
	fpk, err := os.Create(pkFilePath)
	if err != nil {
		return err
	}
	defer fpk.Close()
	_, err = pk.WriteTo(fpk)
	if err != nil {
		return err
	}
	return nil
}

func WriteVk(vkFilePath string, vk native_plonk.VerifyingKey) error {
	exists, err := FileExists(vkFilePath)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(vkFilePath)
		if err != nil {
			return err
		}
	}
	fvk, err := os.Create(vkFilePath)
	if err != nil {
		return err
	}
	defer fvk.Close()
	_, err = vk.WriteTo(fvk)
	if err != nil {
		return err
	}
	return nil
}
func Power2Index(n uint64) int {
	c := bits.OnesCount64(n)
	if c != 1 {
		panic("n must be 2^k")
	}

	t := bits.LeadingZeros64(n)
	if t == 0 {
		panic("next power of 2 overflows uint64")
	}
	return 63 - t
}
