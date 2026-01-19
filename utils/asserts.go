package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func AssertAscendingOrder(comparator *cmp.BoundedComparator, l []frontend.Variable) {
	if comparator == nil {
		panic("comparator must not be nil")
	}
	for i := 1; i < len(l); i++ {
		comparator.AssertIsLessEq(l[i-1], l[i])
	}
}

func AssertDescendingOrder(comparator *cmp.BoundedComparator, l []frontend.Variable) {
	if comparator == nil {
		panic("comparator must not be nil")
	}
	for i := 1; i < len(l); i++ {
		comparator.AssertIsLessEq(l[i], l[i-1])
	}
}

// AssertPermutation verifies that `permuted` is a permutation of `original`
func AssertPermutation(api frontend.API, permuted []frontend.Variable, original []frontend.Variable) {
	AssertPartialDeduplication(api, permuted, original)
	AssertPartialDeduplication(api, original, permuted)
}

// AssertDeduplicationSoundness verifies that `deduped` contains exactly the set of
// unique elements from `original` (no missing elements and no extras).
func AssertDeduplicationSoundness(api frontend.API, deduped []frontend.Variable, original []frontend.Variable) {
	AssertPartialDeduplication(api, deduped, original)
	AssertPartialDeduplication(api, original, deduped)
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
