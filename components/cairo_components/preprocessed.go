package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
)

// NPreprocessedColumns is the number of preprocessed columns for the Canonical layout
const NPreprocessedColumns = 162

// seqColumnMappings lists the canonical IDs for each sequence column.
var seqColumnMappings = []struct {
	logSize int
	id      int
}{
	{logSize: 24, id: 0},
	{logSize: 23, id: 1},
	{logSize: 22, id: 58},
	{logSize: 21, id: 59},
	{logSize: 20, id: 60},
	{logSize: 19, id: 64},
	{logSize: 18, id: 65},
	{logSize: 17, id: 75},
	{logSize: 16, id: 76},
	{logSize: 15, id: 84},
	{logSize: 14, id: 90},
	{logSize: 13, id: 97},
	{logSize: 12, id: 98},
	{logSize: 11, id: 99},
	{logSize: 10, id: 100},
	{logSize: 9, id: 101},
	{logSize: 8, id: 104},
	{logSize: 7, id: 110},
	{logSize: 6, id: 113},
	{logSize: 5, id: 144},
	{logSize: 4, id: 145},
}

// ╔══════════════════════════════════╗
// ║       Preprocessed Columns       ║
// ╚══════════════════════════════════╝

// PreprocessedColumn mimics the Cairo enum variants used to index PreprocessedSampledValues.
type PreprocessedColumn struct {
	id frontend.Variable // unique identifier of the column in [0, NPreprocessedColumns-1]
}

// NewPreprocessedColumnSeq builds a sequence column descriptor using the canonical
// ordering defined in PreprocessedColumns.
func NewPreprocessedColumnSeq(api frontend.API, logSize frontend.Variable) PreprocessedColumn {
	id := frontend.Variable(0)
	matchCount := frontend.Variable(0)
	for _, mapping := range seqColumnMappings {
		isMatch := cmp.IsEqual(api, logSize, frontend.Variable(mapping.logSize))
		id = api.Add(id, api.Mul(isMatch, frontend.Variable(mapping.id)))
		matchCount = api.Add(matchCount, isMatch)
	}
	api.AssertIsEqual(api.Mul(matchCount, api.Sub(frontend.Variable(1), matchCount)), frontend.Variable(0))

	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnPedersenPoints builds a pedersen points column descriptor.
// IDs span 2 to 57 as defined by PreprocessedColumns.
func NewPreprocessedColumnPedersenPoints(api frontend.API, index frontend.Variable) PreprocessedColumn {
	id := api.Add(index, frontend.Variable(2))
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnBitwiseXor builds a bitwise xor column descriptor aligned
// with the canonical ordering.
func NewPreprocessedColumnBitwiseXor(api frontend.API, nBits, columnID frontend.Variable) PreprocessedColumn {
	is4 := cmp.IsEqual(api, nBits, frontend.Variable(4))
	is7 := cmp.IsEqual(api, nBits, frontend.Variable(7))
	is8 := cmp.IsEqual(api, nBits, frontend.Variable(8))
	is9 := cmp.IsEqual(api, nBits, frontend.Variable(9))
	is10 := cmp.IsEqual(api, nBits, frontend.Variable(10))

	base := frontend.Variable(0)
	base = api.Add(base, api.Mul(is10, frontend.Variable(61)))
	base = api.Add(base, api.Mul(is9, frontend.Variable(66)))
	base = api.Add(base, api.Mul(is8, frontend.Variable(77)))
	base = api.Add(base, api.Mul(is7, frontend.Variable(91)))
	base = api.Add(base, api.Mul(is4, frontend.Variable(105)))

	matchCount := api.Add(is10, is9)
	matchCount = api.Add(matchCount, is8)
	matchCount = api.Add(matchCount, is7)
	matchCount = api.Add(matchCount, is4)
	api.AssertIsEqual(matchCount, frontend.Variable(1))

	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck2 builds a range-check (2 values) column
// descriptor that matches the canonical ordering.
func NewPreprocessedColumnRangeCheck2(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	isFirst9 := cmp.IsEqual(api, values[0], frontend.Variable(9))
	isFirst5 := cmp.IsEqual(api, values[0], frontend.Variable(5))
	isFirst4 := cmp.IsEqual(api, values[0], frontend.Variable(4))

	isSecond9 := cmp.IsEqual(api, values[1], frontend.Variable(9))
	isSecond4 := cmp.IsEqual(api, values[1], frontend.Variable(4))
	isSecond3 := cmp.IsEqual(api, values[1], frontend.Variable(3))

	case99 := api.Mul(isFirst9, isSecond9)
	case54 := api.Mul(isFirst5, isSecond4)
	case44 := api.Mul(isFirst4, isSecond4)
	case43 := api.Mul(isFirst4, isSecond3)

	base := frontend.Variable(0)
	base = api.Add(base, api.Mul(case99, frontend.Variable(69)))
	base = api.Add(base, api.Mul(case54, frontend.Variable(102)))
	base = api.Add(base, api.Mul(case44, frontend.Variable(108)))
	base = api.Add(base, api.Mul(case43, frontend.Variable(111)))

	matchCount := api.Add(api.Add(case99, case54), api.Add(case44, case43))
	api.AssertIsEqual(matchCount, frontend.Variable(1))

	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck3 builds a range-check (3 values) column descriptor.
func NewPreprocessedColumnRangeCheck3(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	api.AssertIsEqual(values[0], frontend.Variable(7))
	api.AssertIsEqual(values[1], frontend.Variable(2))
	api.AssertIsEqual(values[2], frontend.Variable(5))

	base := frontend.Variable(94)
	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck4 builds a range-check (4 values) column descriptor.
func NewPreprocessedColumnRangeCheck4(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	isFirst3 := cmp.IsEqual(api, values[0], frontend.Variable(3))
	isFirst4 := cmp.IsEqual(api, values[0], frontend.Variable(4))
	isSecond6 := cmp.IsEqual(api, values[1], frontend.Variable(6))
	isSecond4 := cmp.IsEqual(api, values[1], frontend.Variable(4))
	isThird6 := cmp.IsEqual(api, values[2], frontend.Variable(6))
	isThird4 := cmp.IsEqual(api, values[2], frontend.Variable(4))
	isFourth3 := cmp.IsEqual(api, values[3], frontend.Variable(3))
	isFourth4 := cmp.IsEqual(api, values[3], frontend.Variable(4))

	case3663 := api.Mul(isFirst3, isSecond6)
	case3663 = api.Mul(case3663, isThird6)
	case3663 = api.Mul(case3663, isFourth3)

	case4444 := api.Mul(isFirst4, isSecond4)
	case4444 = api.Mul(case4444, isThird4)
	case4444 = api.Mul(case4444, isFourth4)

	base := frontend.Variable(0)
	base = api.Add(base, api.Mul(case3663, frontend.Variable(71)))
	base = api.Add(base, api.Mul(case4444, frontend.Variable(80)))

	matchCount := api.Add(case3663, case4444)
	api.AssertIsEqual(matchCount, frontend.Variable(1))

	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck5 builds a range-check (5 values) column descriptor.
func NewPreprocessedColumnRangeCheck5(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(values[i], frontend.Variable(3))
	}
	base := frontend.Variable(85)
	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnPoseidonRoundKeys builds a poseidon round keys column descriptor.
func NewPreprocessedColumnPoseidonRoundKeys(api frontend.API, index frontend.Variable) PreprocessedColumn {
	base := frontend.Variable(114)
	id := api.Add(base, index)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnBlakeSigma builds a blake sigma column descriptor.
// Occupy range 146 to 161 (inclusive)
func NewPreprocessedColumnBlakeSigma(api frontend.API, index frontend.Variable) PreprocessedColumn {
	base := frontend.Variable(146)
	id := api.Add(base, index)
	return PreprocessedColumn{
		id: id,
	}
}

// Key encodes the column using the same packing logic as the Cairo PreprocessedColumnKey.
func (column PreprocessedColumn) Key() frontend.Variable {
	return column.id
}

// ╔══════════════════════════════════╗
// ║    Preprocessed Sampled Values   ║
// ╚══════════════════════════════════╝

// PreprocessedSampledValues is a wrapper around a table of sampled values for the preprocessed trace.
// It provides the Get() method to access the sampled values for a given column.
// Note that is needed since components don't always use the same preprocessed columns (e.g. MemoryAddressToID)
type PreprocessedSampledValues struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	values logderivlookup.Table
}

// NewPreprocessedSampledValues builds a PreprocessedSampledValues from a slice of sampled values.
func NewPreprocessedSampledValues(api frontend.API, qm31 *m31.QM31Chip, preprocessedSampledValuesRaw [][]m31.QM31) PreprocessedSampledValues {
	values := logderivlookup.New(api)

	for i := range NPreprocessedColumns {
		columnValues := preprocessedSampledValuesRaw[i]

		switch len(columnValues) {
		case 0:
			values.Insert(frontend.Variable(0)) // unused preprocessed column
		case 1:
			encodedValue := qm31.EncodeNative(columnValues[0])
			values.Insert(encodedValue)
		default:
			panic("preprocessed column has more than 1 sampled value")
		}
	}

	return PreprocessedSampledValues{
		api:    api,
		qm31:   qm31,
		values: values,
	}
}

// Get returns the sampled value for the provided column
func (ps PreprocessedSampledValues) Get(column PreprocessedColumn) m31.QM31 {
	key := column.Key()
	encodedValue := ps.values.Lookup(key)[0]
	value := ps.qm31.DecodeNative(encodedValue)
	return value
}
