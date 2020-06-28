/*
	Original Copyright 2015 https://gitlab.com/NebulousLabs
*/

/*
The MIT License (MIT)

Copyright (c) 2015 Nebulous

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package merkle

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
)

// nbBits in an Fr element
// TODO this shouldn't be a constant, but don't know how to to avoid passing it to every function
const nbBits = 256

// leafSum returns the hash created from data inserted to form a leaf. Leaf
// sums are calculated using:
//		Hash(0x00 || data)
func leafSumDeprecated(circuit *frontend.CS, h mimc.MiMCGadget, data *frontend.Constraint) *frontend.Constraint {

	// TODO find a better way than querying the binary decomposition, too many constraints
	dataBin := circuit.TO_BINARY(data, nbBits)

	// prepending 0x00 means the first chunk to be hashed will consist of the first 31 bytes
	d1 := circuit.FROM_BINARY(dataBin[8:]...)

	// the lsByte of data will become the lsByte of the second chunk
	d2 := circuit.FROM_BINARY(dataBin[:8]...)

	res := h.Hash(circuit, d1, d2)
	//res := h.Hash(circuit, d1)

	return res
}

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafSum(circuit *frontend.CS, h mimc.MiMCGadget, data *frontend.Constraint) *frontend.Constraint {

	res := h.Hash(circuit, data)

	return res
}

// nodeSum returns the hash created from two sibling nodes being combined into
// a parent node. Node sums are calculated using:
//		Hash(0x01 || left sibling sum || right sibling sum)
func nodeSumDeprecated(circuit *frontend.CS, h mimc.MiMCGadget, a, b *frontend.Constraint) *frontend.Constraint {

	// TODO find a better way than querying the binary decomposition (too many constraints)
	d1Bin := circuit.TO_BINARY(a, nbBits)
	d2Bin := circuit.TO_BINARY(b, nbBits)

	// multiplying by shifter shifts a number by 31*8 bits
	var shifter big.Int
	shifter.SetString("452312848583266388373324160190187140051835877600158453279131187530910662656", 10) // 1 << (31*8)

	// pefix 0x01
	chunk1 := circuit.FROM_BINARY(d1Bin[8:]...)
	chunk1 = circuit.ADD(chunk1, shifter) // adding shifter is equivalent to prefix chunk1 by 0x01

	// lsByte(a)<<31*8 || (b>>8)
	chunk2 := circuit.FROM_BINARY(d1Bin[:8]...) // lsByte(a)
	chunk2 = circuit.MUL(chunk2, shifter)       // chunk2 = lsByte(a)<<31*8
	tmp := circuit.FROM_BINARY(d2Bin[8:]...)
	chunk2 = circuit.ADD(chunk2, tmp) // chunk2 = chunk2 || (b>>8)

	// lsByte(b)
	chunk3 := circuit.FROM_BINARY(d2Bin[:8]...)
	//chunk3 = circuit.MUL(chunk3, shifter)

	res := h.Hash(circuit, chunk1, chunk2, chunk3)

	return res

}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(circuit *frontend.CS, h mimc.MiMCGadget, a, b *frontend.Constraint) *frontend.Constraint {

	res := h.Hash(circuit, a, b)

	return res
}

// GenerateProofHelper generates an array of 1 or 0 telling if during the proof verification
// the hash to compute is h(sum, proof[i]) or h(proof[i], sum). The size of the resulting slice is
// len(proofSet)-1.
// cf gitlab.com/NebulousLabs/merkletree for the algorithm
func GenerateProofHelper(proofSet [][]byte, proofIndex, numLeaves uint64) []int {

	res := make([]int, len(proofSet)-1)

	height := 1

	// While the current subtree (of height 'height') is complete, determine
	// the position of the next sibling using the complete subtree algorithm.
	// 'stableEnd' tells us the ending index of the last full subtree. It gets
	// initialized to 'proofIndex' because the first full subtree was the
	// subtree of height 1, created above (and had an ending index of
	// 'proofIndex').
	stableEnd := proofIndex
	for {
		// Determine if the subtree is complete. This is accomplished by
		// rounding down the proofIndex to the nearest 1 << 'height', adding 1
		// << 'height', and comparing the result to the number of leaves in the
		// Merkle tree.
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height)) // round down to the nearest 1 << height
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1              // subtract 1 because the start index is inclusive
		if subTreeEndIndex >= numLeaves {
			// If the Merkle tree does not have a leaf at index
			// 'subTreeEndIndex', then the subtree of the current height is not
			// a complete subtree.
			break
		}
		stableEnd = subTreeEndIndex

		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			res[height-1] = 1
		} else {
			res[height-1] = 0
		}
		height++
	}

	// Determine if the next hash belongs to an orphan that was elevated. This
	// is the case IFF 'stableEnd' (the last index of the largest full subtree)
	// is equal to the number of leaves in the Merkle tree.
	if stableEnd != numLeaves-1 {
		res[height-1] = 1
		height++
	}

	// All remaining elements in the proof set will belong to a left sibling.
	for height < len(proofSet) {
		res[height-1] = 0
		height++
	}

	return res
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(circuit *frontend.CS, h mimc.MiMCGadget, merkleRoot *frontend.Constraint, proofSet, helper []*frontend.Constraint) {

	sum := leafSum(circuit, h, proofSet[0])

	for i := 1; i < len(proofSet); i++ {
		circuit.MUSTBE_BOOLEAN(helper[i-1])
		d1 := circuit.SELECT(helper[i-1], sum, proofSet[i])
		d2 := circuit.SELECT(helper[i-1], proofSet[i], sum)
		sum = nodeSum(circuit, h, d1, d2)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	circuit.MUSTBE_EQ(sum, merkleRoot)

}
