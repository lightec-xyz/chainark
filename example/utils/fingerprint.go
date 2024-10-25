package utils

import (
	"math/big"
	"os"
	"slices"

	"github.com/consensys/gnark-crypto/hash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/lightec-xyz/chainark"
)

func VerifyingKeyMiMCHash[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](h hash.Hash, vk plonk.VerifyingKey[FR, G1El, G2El]) ([]byte, error) {
	mimc := h.New()

	mimc.Write(big.NewInt(int64(vk.BaseVerifyingKey.NbPublicVariables)).Bytes())
	mimc.Write(big.NewInt(int64(vk.CircuitVerifyingKey.Size.(uint64))).Bytes())
	{
		for i := 0; i < len(vk.Generator.Limbs); i++ {
			mimc.Write(vk.Generator.Limbs[i].(*big.Int).Bytes())
		}
	}

	comms := make([]kzg.Commitment[G1El], 0)
	comms = append(comms, vk.CircuitVerifyingKey.S[:]...)
	comms = append(comms, vk.CircuitVerifyingKey.Ql)
	comms = append(comms, vk.CircuitVerifyingKey.Qr)
	comms = append(comms, vk.CircuitVerifyingKey.Qm)
	comms = append(comms, vk.CircuitVerifyingKey.Qo)
	comms = append(comms, vk.CircuitVerifyingKey.Qk)
	comms = append(comms, vk.CircuitVerifyingKey.Qcp[:]...)

	for _, comm := range comms {
		el := comm.G1El
		switch r := any(&el).(type) {
		case *sw_bn254.G1Affine:
			for i := 0; i < len(r.X.Limbs); i++ {
				mimc.Write(r.X.Limbs[i].(*big.Int).Bytes())
			}
			for i := 0; i < len(r.Y.Limbs); i++ {
				mimc.Write(r.Y.Limbs[i].(*big.Int).Bytes())
			}
		default:
			panic("unknown parametric type")
		}
	}

	for i := 0; i < len(vk.CircuitVerifyingKey.CommitmentConstraintIndexes); i++ {
		mimc.Write(big.NewInt(int64(vk.CircuitVerifyingKey.CommitmentConstraintIndexes[i].(uint64))).Bytes())
	}

	result := mimc.Sum(nil)
	slices.Reverse(result)
	return result, nil
}

func UnsafeFingerPrintFromVk[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vk native_plonk.VerifyingKey) ([]byte, error) {
	circuitVk, err := plonk.ValueOfVerifyingKey[FR, G1El, G2El](vk)
	if err != nil {
		return nil, err
	}
	fpBytes, err := VerifyingKeyMiMCHash[FR, G1El, G2El](hash.MIMC_BN254, circuitVk)
	if err != nil {
		return nil, err
	}
	return fpBytes, nil
}

func UnsafeFingerPrintFromVkFile[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vkFile string) ([]byte, error) {
	var (
		err     error
		bn254Vk plonk_bn254.VerifyingKey
	)

	fvk, err := os.Open(vkFile)
	defer fvk.Close()
	if err != nil {
		return nil, err
	}
	_, err = bn254Vk.ReadFrom(fvk)
	if err != nil {
		return nil, err
	}
	return UnsafeFingerPrintFromVk[FR, G1El, G2El, GtEl](&bn254Vk)
}

func AssertFpInSet(api frontend.API, fp frontend.Variable, fpSet []chainark.FingerPrintBytes, fpBitsPerVar int) {
	fpv, err := chainark.FpValueOf(api, fp, fpBitsPerVar)
	if err != nil {
		panic(err)
	}

	sum := frontend.Variable(0)
	for i := 0; i < len(fpSet); i++ {
		v := chainark.FingerPrintFromBytes(fpSet[i], fpBitsPerVar)
		t := fpv.IsEqual(api, v)
		sum = api.Or(t, sum)
	}
	api.AssertIsEqual(sum, 1)
}
