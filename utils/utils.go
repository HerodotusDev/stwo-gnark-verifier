package utils

// Are considered utils functions that are built directly on top of the gnark library

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// FlattenTree flattens a tree of slices into a single slice.
func FlattenTree[T any](tree [][]T) []T {
	result := make([]T, 0)
	for _, group := range tree {
		result = append(result, group...)
	}
	return result
}

// U32SliceToNativeSlice converts a slice of uints.U32 to a slice of frontend.Variable.
func U32SliceToNativeSlice(api frontend.API, uapi *uints.BinaryField[uints.U32], l []uints.U32) []frontend.Variable {
	out := make([]frontend.Variable, len(l))
	for i, e := range l {
		out[i] = uapi.ToValue(e)
	}
	return out
}

// BlowupLogSizes blows up the log sizes by the given factor.
func BlowupLogSizes(api frontend.API, logSizes []frontend.Variable, blowupFactor uints.U32) []frontend.Variable {
	if len(logSizes) == 0 {
		return nil
	}
	out := make([]frontend.Variable, len(logSizes))
	for i, size := range logSizes {
		out[i] = api.Add(size, blowupFactor)
	}
	return out
}

// Pow computes base^exponent using the binary decomposition of the exponent. (util should be elsewhere)
func Pow(api frontend.API, cmp *cmp.BoundedComparator, base, exponent frontend.Variable) frontend.Variable {
	one := frontend.Variable(1)
	result := one

	for i := 0; i < 32; i++ {
		isLess := cmp.IsLess(frontend.Variable(i), exponent)
		result = api.Select(isLess, api.Mul(result, base), one)
	}

	return result
}

// SelectHash selects between two [32]uints.U8 based on a frontend.Variable condition.
func SelectHash(api frontend.API, condition frontend.Variable, hash0, hash1 [32]uints.U8) [32]uints.U8 {
	result := [32]uints.U8{}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 32; i++ {
		result[i] = uapi.Select(condition, hash0[i], hash1[i])
	}
	return result
}

// GenerateQueries folds the base layer queries and deduplicates them layer by layer.
// It returns the deduplicated queries for all layers from root to leaves (exactly maxLogSize + 1 layers).
func GenerateQueries(api frontend.API, baseLayerQueries []frontend.Variable, nQueries uint8, dedupedQueriesShape []int, maxLogSize uint8) [][]frontend.Variable {
	// initialize the queries array (containing duplicates and that can be computed statically)
	queries := make([][]frontend.Variable, maxLogSize+1)
	queriesDeduped := make([][]frontend.Variable, maxLogSize+1)

	// deduplicate the base layer queries
	queries[maxLogSize] = baseLayerQueries
	layerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, dedupedQueriesShape[maxLogSize], queries[maxLogSize]...)
	if err != nil {
		panic(err)
	}
	AssertPartialDeduplication(api, layerQueriesDeduped, queries[maxLogSize])
	queriesDeduped[maxLogSize] = layerQueriesDeduped

	// build all queries above the base layer
	for l := maxLogSize; l >= 1; l-- {
		// compute the queries for the next layer (not deduplicated)
		queries[l-1] = make([]frontend.Variable, dedupedQueriesShape[l])
		if dedupedQueriesShape[l] > 0 {
			for queryIndex := 0; queryIndex < dedupedQueriesShape[l]; queryIndex++ {
				parentQueryBinary := api.ToBinary(queriesDeduped[l][queryIndex], 32)
				parentQueryShifted := api.FromBinary(parentQueryBinary[1:]...)
				queries[l-1][queryIndex] = parentQueryShifted
			}
		}

		// deduplicate the queries for the next layer
		nextLayerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, dedupedQueriesShape[l-1], queries[l-1]...)
		if err != nil {
			panic(err)
		}
		AssertPartialDeduplication(api, nextLayerQueriesDeduped, queries[l-1])
		queriesDeduped[l-1] = nextLayerQueriesDeduped
	}

	return queriesDeduped
}

// ToLookupTable converts a slice of slices of frontend.Variable to a slice of lookup tables.
func ToLookupTable(api frontend.API, queries [][]frontend.Variable) []logderivlookup.Table {
	lookupTables := make([]logderivlookup.Table, len(queries))
	for i, layerQueries := range queries {
		lookupTables[i] = logderivlookup.New(api)
		for _, query := range layerQueries {
			lookupTables[i].Insert(query)
		}
		// We append a dummy query to the end of the lookup table, this is because when handling the last query (queries[j])
		// of a layer the vcs verifier also accesses the next query (queries[j+1]).
		// We use a dummy query that is greater than all possible queries to have an error in case it is used
		lookupTables[i].Insert(frontend.Variable(1 << 32))
	}
	return lookupTables
}

// SplitHash splits a [32]uints.U8 into two 128-bit frontend.Variables.
func SplitHash(api frontend.API, hash [32]uints.U8) (frontend.Variable, frontend.Variable) {
	lo, err := conversion.BytesToNative(api, hash[:16])
	if err != nil {
		panic(err)
	}
	hi, err := conversion.BytesToNative(api, hash[16:])
	if err != nil {
		panic(err)
	}
	return lo, hi
}

// RebuildHash rebuilds a [32]uints.U8 from two 128-bit frontend.Variables.
func RebuildHash(api frontend.API, lo, hi frontend.Variable) [32]uints.U8 {
	loBytes, err := conversion.NativeToBytes(api, lo)
	if err != nil {
		panic(err)
	}
	nLoBytes := len(loBytes)
	hiBytes, err := conversion.NativeToBytes(api, hi)
	if err != nil {
		panic(err)
	}
	nHiBytes := len(hiBytes)
	hash := [32]uints.U8{}
	for i := 0; i < 16; i++ {
		hash[i] = loBytes[nLoBytes-16+i]
		hash[i+16] = hiBytes[nHiBytes-16+i]
	}
	return hash
}
