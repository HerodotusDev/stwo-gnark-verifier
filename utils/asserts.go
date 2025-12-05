package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// AssertAscendingOrder verifies that `l` is in ascending order (elements need to be less than 1<<32)
func AssertAscendingOrder(api frontend.API, l []frontend.Variable) {
	cmp := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)
	for i := 1; i < len(l); i++ {
		cmp.AssertIsLess(l[i-1], l[i])
	}
}

// AssertDescendingOrder verifies that `l` is in descending order (elements need to be greater than 1<<32)
func AssertDescendingOrder(api frontend.API, l []frontend.Variable) {
	cmp := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)
	for i := 1; i < len(l); i++ {
		cmp.AssertIsLess(l[i], l[i-1])
	}
}

// AssertPermutation verifies that `permuted` is a permutation of `original`
func AssertPermutation(api frontend.API, permuted []frontend.Variable, original []frontend.Variable) {
	AssertPartialDeduplication(api, permuted, original)
	AssertPartialDeduplication(api, original, permuted)
}

// AssertPartialDeduplication verifies that `partiallyDeduplicated` contains all elements of `original` but
// appearing fewer or as many times as in `original`.
// We check that all elements of original are roots of the polynomial that vanishes on the elements of partiallyDeduplicated.
func AssertPartialDeduplication(api frontend.API, partiallyDeduplicated []frontend.Variable, original []frontend.Variable) {
	for _, e := range original {
		prod := frontend.Variable(1)
		for _, d := range partiallyDeduplicated {
			prod = api.Mul(prod, api.Sub(d, e))
		}
		api.AssertIsEqual(prod, frontend.Variable(0))
	}
}
