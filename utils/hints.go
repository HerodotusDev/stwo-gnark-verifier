package utils

import (
	"math/big"
	"sort"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(DeduplicationHint)
	solver.RegisterHint(AscendingOrderHint)
	solver.RegisterHint(DescendingOrderHint)
}

// DeduplicationHint takes a list of big.Ints and returns its deduplicated version.
func DeduplicationHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	seen := make(map[string]bool)
	unique := make([]*big.Int, 0)
	for _, e := range inputs {
		key := e.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}
	for i := 0; i < len(results) && i < len(unique); i++ {
		results[i] = new(big.Int).Set(unique[i])
	}
	return nil
}

// AscendingOrderHint takes a list of big.Ints and returns its ascending ordered version.
func AscendingOrderHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Cmp(inputs[j]) < 0 })
	for i := 0; i < len(results) && i < len(inputs); i++ {
		results[i] = new(big.Int).Set(inputs[i])
	}
	return nil
}

// DescendingOrderHint takes a list of big.Ints and returns its descending ordered version.
func DescendingOrderHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Cmp(inputs[j]) > 0 })
	for i := 0; i < len(results) && i < len(inputs); i++ {
		results[i] = new(big.Int).Set(inputs[i])
	}
	return nil
}
