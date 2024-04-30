package common

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
)

type BinaryMerkleTree [][LenOfHash]byte

func BuildBinaryMerkleTree(leaves [][LenOfHash]byte) BinaryMerkleTree {
	l := int(ecc.NextPowerOfTwo(uint64(len(leaves))))
	zeroPadding := make([][LenOfHash]byte, l-len(leaves))
	tree := make([][LenOfHash]byte, 2*l)

	copy(tree[l:], leaves)
	copy(tree[l+len(leaves):], zeroPadding)

	for i := l - 1; i > 0; i-- {
		tree[i] = sha256.Sum256(append(tree[2*i][:], tree[2*i+1][:]...))
	}

	return tree
}

func (tree BinaryMerkleTree) Root() [LenOfHash]byte {
	return tree[1]
}

func (tree BinaryMerkleTree) Proof(index uint64) ([][LenOfHash]byte, error) {
	if index < uint64(len(tree)/2) {
		return nil, fmt.Errorf("invalid leaf index")
	}
	proof := make([][LenOfHash]byte, 0)

	for i := index; i > 1; i /= 2 {
		sibling := [LenOfHash]byte{}
		if i%2 == 0 {
			copy(sibling[:], tree[i+1][:])
		} else {
			copy(sibling[:], tree[i-1][:])
		}
		proof = append(proof, sibling)
	}
	return proof, nil
}

func RestoreMerkleRoot(index uint64, leaf [LenOfHash]byte, branches [][LenOfHash]byte) [LenOfHash]byte {
	var value = leaf

	for i := 0; i < len(branches); i++ {
		isRight := (index>>i)&0x01 == 1 //isRight = 1, value is right child, else value is left child
		if isRight {
			input := append(branches[i][:], value[:]...)
			value = sha256.Sum256(input)
		} else {
			input := append(value[:], branches[i][:]...)
			value = sha256.Sum256(input)
		}
	}
	return value
}
