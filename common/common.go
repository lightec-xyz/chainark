package common

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"os"
	"reflect"
)

func NewConstraintSystem(circuit frontend.Circuit) (constraint.ConstraintSystem, error) {
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	if err != nil {
		return nil, err
	}
	return ccs, nil
}

func InitPkVk(ccs constraint.ConstraintSystem, srs *kzg.SRS, srsLagrange *kzg.SRS) (native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {
	pk, vk, err := native_plonk.Setup(ccs, *srs, *srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, err
}

func PlonkProve(assignment frontend.Circuit, pk native_plonk.ProvingKey, ccs constraint.ConstraintSystem) (native_plonk.Proof, witness.Witness, error) {
	innerField := ecc.BN254.ScalarField()
	outerField := ecc.BN254.ScalarField()
	wit, err := frontend.NewWitness(assignment, innerField)
	if err != nil {
		return nil, nil, err
	}
	proof, err := native_plonk.Prove(ccs, pk, wit, recursive_plonk.GetNativeProverOptions(outerField, innerField))
	if err != nil {
		return nil, nil, err
	}
	return proof, wit, nil
}

func PlonkVerify(assignment frontend.Circuit, proof native_plonk.Proof, vk native_plonk.VerifyingKey) error {
	innerField := ecc.BN254.ScalarField()
	outerField := ecc.BN254.ScalarField()
	wit, err := frontend.NewWitness(assignment, innerField)
	if err != nil {
		return err
	}
	pubWit, err := wit.Public()
	if err != nil {
		return err
	}
	err = native_plonk.Verify(proof, vk, pubWit, recursive_plonk.GetNativeVerifierOptions(outerField, innerField))
	if err != nil {
		return err
	}
	return nil
}

func GetObj(filePath string, value interface{}) error {
	if reflect.ValueOf(value).Kind() != reflect.Ptr {
		return fmt.Errorf("value mutst be a pointer")
	}
	dataBytes, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(dataBytes, value)
	if err != nil {
		return err
	}
	return err
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat error: %v", err)
}
