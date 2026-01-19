package utils

// Are considered utils functions that are built directly on top of the gnark library

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║         Conversion Utils         ║
// ╚══════════════════════════════════╝

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

// ToLookupTable converts a slice of slices of frontend.Variable to a slice of lookup tables.
func ToLookupTable(api frontend.API, table [][]frontend.Variable) []logderivlookup.Table {
	lookupTables := make([]logderivlookup.Table, len(table))
	for i, slice := range table {
		lookupTables[i] = logderivlookup.New(api)
		for _, value := range slice {
			lookupTables[i].Insert(value)
		}
		// We append a dummy value to the end of the lookup table.
		// This is because when, for instance, handling the last query (queries[j]) of a layer the vcs verifier also
		// accesses the next query (queries[j+1]). We use a dummy query that is greater than all possible queries to
		// have an error in case it is used. Same for fri quotient evaluations.
		lookupTables[i].Insert(frontend.Variable(1 << 32))
	}
	return lookupTables
}

// AppendDummy appends a dummy value to each inner slice and returns a deep copy.
// Useful when code expects a sentinel element for constant-index access.
func AppendDummy(table [][]frontend.Variable, dummy frontend.Variable) [][]frontend.Variable {
	out := make([][]frontend.Variable, len(table))
	for i, slice := range table {
		copied := append([]frontend.Variable(nil), slice...)
		copied = append(copied, dummy)
		out[i] = copied
	}
	return out
}

// BlowupLogSizes blows up the log sizes by the given factor.
func BlowupLogSizes(api frontend.API, logSizes []frontend.Variable, blowupFactor frontend.Variable) []frontend.Variable {
	if len(logSizes) == 0 {
		return nil
	}
	out := make([]frontend.Variable, len(logSizes))
	for i, size := range logSizes {
		out[i] = api.Add(size, blowupFactor)
	}
	return out
}

// ╔══════════════════════════════════╗
// ║           Query Utils            ║
// ╚══════════════════════════════════╝

// GenerateQueries folds the base layer queries and deduplicates them layer by layer.
// It returns the deduplicated queries for all layers from root to leaves (exactly maxLogSize + 1 layers).
//
// Callers should construct the comparator once (e.g. in a higher-level chip) and reuse it to avoid repeated gadget initialization.
func GenerateQueries(api frontend.API, uapi *uints.BinaryField[uints.U32], comparator *cmp.BoundedComparator, baseLayerQueries []frontend.Variable, _ uint8, dedupedQueriesShape []int, maxLogSize uint8) [][]frontend.Variable {
	if comparator == nil {
		panic("comparator must not be nil")
	}
	// initialize the queries array
	queriesDeduped := make([][]frontend.Variable, maxLogSize+1)

	// deduplicate and order the base layer queries
	layerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, dedupedQueriesShape[maxLogSize], baseLayerQueries...)
	if err != nil {
		panic(err)
	}
	layerQueriesDedupedOrdered, err := api.Compiler().NewHint(AscendingOrderHint, dedupedQueriesShape[maxLogSize], layerQueriesDeduped...)
	if err != nil {
		panic(err)
	}
	AssertDeduplicationSoundness(api, layerQueriesDedupedOrdered, baseLayerQueries)
	AssertAscendingOrder(comparator, layerQueriesDedupedOrdered)
	queriesDeduped[maxLogSize] = layerQueriesDedupedOrdered

	// build all queries above the base layer
	for l := maxLogSize; l >= 1; l-- {
		queriesDeduped[l-1] = FoldQueries(api, uapi, comparator, queriesDeduped[l], dedupedQueriesShape[l-1])
	}

	return queriesDeduped
}

// FoldQueries folds the src layer queries and deduplicates/orders them, reusing a caller-provided comparator.
func FoldQueries(api frontend.API, uapi *uints.BinaryField[uints.U32], comparator *cmp.BoundedComparator, srcQueries []frontend.Variable, nDeduplicatedQueries int) []frontend.Variable {
	if comparator == nil {
		panic("comparator must not be nil")
	}
	// compute the queries for the dst layer (not deduplicated)
	dstQueries := make([]frontend.Variable, len(srcQueries))
	for queryIndex := 0; queryIndex < len(srcQueries); queryIndex++ {
		parentQueryU32 := uapi.ValueOf(srcQueries[queryIndex])
		parentQueryShifted := uapi.Rshift(parentQueryU32, 1)
		dstQueries[queryIndex] = uapi.ToValue(parentQueryShifted)
	}

	// deduplicate the queries for the dst layer
	nextLayerQueriesDeduped, err := api.Compiler().NewHint(DeduplicationHint, nDeduplicatedQueries, dstQueries...)
	if err != nil {
		panic(err)
	}
	dstQueriesOrdered, err := api.Compiler().NewHint(AscendingOrderHint, nDeduplicatedQueries, nextLayerQueriesDeduped...)
	if err != nil {
		panic(err)
	}
	AssertDeduplicationSoundness(api, dstQueriesOrdered, dstQueries)
	AssertAscendingOrder(comparator, dstQueriesOrdered)
	return dstQueriesOrdered
}

// ╔══════════════════════════════════╗
// ║           Hashing utils		  ║
// ╚══════════════════════════════════╝

// SelectHashWithUAPI is the same as SelectHash but reuses a caller-provided uapi.
func SelectHashWithUAPI(uapi *uints.BinaryField[uints.U32], condition frontend.Variable, hash0, hash1 [32]uints.U8) [32]uints.U8 {
	if uapi == nil {
		panic("uapi must not be nil")
	}
	result := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		result[i] = uapi.Select(condition, hash0[i], hash1[i])
	}
	return result
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

// ╔══════════════════════════════════╗
// ║            Math Utils            ║
// ╚══════════════════════════════════╝

// Pow computes base^exponent using the binary decomposition of the exponent. (util should be elsewhere)
func Pow(api frontend.API, cmp *cmp.BoundedComparator, base, exponent frontend.Variable) frontend.Variable {
	one := frontend.Variable(1)
	result := one

	for i := 0; i < 32; i++ {
		isLess := cmp.IsLess(frontend.Variable(i), exponent)
		result = api.Select(isLess, api.Mul(result, base), result)
	}

	return result
}

// Pow2 computes 2^exponent using a fixed-width binary decomposition.
// nbBits should cover the maximum exponent bit-length in the circuit.
func Pow2(api frontend.API, exponent frontend.Variable, nbBits int) frontend.Variable {
	if nbBits <= 0 {
		return frontend.Variable(1)
	}
	bits := bits.ToBinary(api, exponent, bits.WithNbDigits(nbBits))
	result := frontend.Variable(1)
	for i := 0; i < nbBits; i++ {
		// multiplier = 2^(2^i) as a constant field element
		multiplier := new(big.Int).Lsh(big.NewInt(1), uint(1<<i))
		// result *= multiplier if bit=1
		result = api.Mul(result, api.Add(api.Mul(bits[i], api.Sub(multiplier, 1)), 1))
	}
	return result
}
