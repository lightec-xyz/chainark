package common

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/hash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	"math/big"
	"slices"
)

func PubKeysMiMCHash(h hash.Hash, pubKeys [][]byte) ([]byte, error) {
	mimc := h.New()
	nbLimbs := emulated.BLS12381Fp{}.NbLimbs()
	nbBitsPerLimb := emulated.BLS12381Fp{}.BitsPerLimb()

	for _, pubKey := range pubKeys {
		g1 := bls12381.G1Affine{}
		err := g1.Unmarshal(pubKey)
		if err != nil {
			return nil, err
		}

		x := big.NewInt(0)
		y := big.NewInt(0)
		g1.X.BigInt(x)
		g1.Y.BigInt(y)

		xLimbs := make([]*big.Int, nbLimbs)
		yLimbs := make([]*big.Int, nbLimbs)

		base := big.NewInt(0).Lsh(big.NewInt(1), nbBitsPerLimb)
		for k := 0; k < 6; k++ {
			xLimbs[k] = big.NewInt(0).Mod(x, base)
			x.Rsh(x, 64)
			yLimbs[k] = big.NewInt(0).Mod(y, base)
			y.Rsh(y, 64)
		}

		for k := uint(0); k < nbLimbs; k++ {
			mimc.Write(xLimbs[k].Bytes())
		}
		for k := uint(0); k < nbLimbs; k++ {
			mimc.Write(yLimbs[k].Bytes())
		}
	}
	return mimc.Sum(nil), nil
}

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
