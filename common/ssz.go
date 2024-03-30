package common

import (
	"crypto/sha256"
	"encoding/binary"
)

func sszLayer(input []byte) []byte {
	if len(input) < 64 || len(input)%64 != 0 {
		panic("Invalid input length")
	}

	nbPairs := len(input) / 64
	output := make([]byte, nbPairs*LenOfHash)
	for i := 0; i < nbPairs; i++ {
		hasher := sha256.New()
		hasher.Write(input[i*64 : (i+1)*64])
		copy(output[i*32:(i+1)*32], hasher.Sum(nil))
	}
	return output
}

func SSZRoot(
	input []byte,
	depth int,
) []byte {
	if len(input) != 32*(1<<depth) {
		panic("Invalid input length")
	}

	layerInput := make([]byte, len(input))
	copy(layerInput, input)

	for i := 0; i < depth; i++ {
		layerInput = sszLayer(layerInput)
	}

	return layerInput
}

func SSZQuarterSyncCommittee(pubKeys [QuarterLenOfValidators][LenOfPubKey]byte) []byte {
	publicKeysInput := []byte{}
	zeroPadding := [16]byte{}

	for i := 0; i < QuarterLenOfValidators; i++ {
		publicKeysInput = append(publicKeysInput, pubKeys[i][:]...)
		publicKeysInput = append(publicKeysInput, zeroPadding[:]...)
	}
	publicKeysRoot := SSZRoot(publicKeysInput[:], 8)

	return publicKeysRoot
}

func SSZSyncCommittee(pubKeys [LenOfValidators][LenOfPubKey]byte, aggPubKey []byte) []byte {
	publicKeysInput := []byte{}
	zeroPadding := [16]byte{}

	for i := 0; i < LenOfValidators; i++ {
		publicKeysInput = append(publicKeysInput, pubKeys[i][:]...)
		publicKeysInput = append(publicKeysInput, zeroPadding[:]...)
	}
	publicKeysRoot := SSZRoot(publicKeysInput[:], 10)

	aggPubKeyInput := append(aggPubKey[:], zeroPadding[:]...)
	aggPubKeyRoot := SSZRoot(aggPubKeyInput[:], 1)

	syncCommitteeInput := append(publicKeysRoot[:], aggPubKeyRoot[:]...)
	syncCommitteeRoot := SSZRoot(syncCommitteeInput[:], 1)

	return syncCommitteeRoot
}

func U64To32LittleEndianBytes(val uint64) [32]byte {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:], val)
	return buf
}
