package common

import (
	"encoding/hex"
)

func DecodeHex(hexString string) []byte {
	if hexString[0:2] == "0x" {
		hexString = hexString[2:]
	}
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return decoded
}

func DecodeHexTo32Bytes(hexString string) [LenOfHash]byte {
	if hexString[0:2] == "0x" {
		hexString = hexString[2:]
	}
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	if len(decoded) != LenOfHash {
		panic("Invalid input length")
	}

	var output [LenOfHash]byte
	copy(output[:], decoded[:LenOfHash])

	return output
}

func DecodeHexTo48Bytes(hexString string) [LenOfPubKey]byte {
	if hexString[0:2] == "0x" {
		hexString = hexString[2:]
	}
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	if len(decoded) != LenOfPubKey {
		panic("Invalid input length")
	}

	var output [LenOfPubKey]byte
	copy(output[:], decoded[:LenOfPubKey])

	return output
}

func AggregationBytesToAggregationBits(input []uint8) [LenOfValidators]uint8 {
	if len(input) != LenOfAggregationBytes {
		panic("Invalid aggregation bytes  length")
	}
	var output [LenOfValidators]uint8
	for byteIndex, byteVal := range input {
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			index := byteIndex*8 + bitIndex
			output[index] = (byteVal >> bitIndex) & 1
		}
	}
	return output
}
