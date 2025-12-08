package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
)

const NPreprocessedColumns = 162

// ╔══════════════════════════════════╗
// ║       Preprocessed Columns       ║
// ╚══════════════════════════════════╝

// PreprocessedColumn mimics the Cairo enum variants used to index preprocessed mask values.
type PreprocessedColumn struct {
	id frontend.Variable // unique identifier of the column in [0, NPreprocessedColumns-1]
}

// NewPreprocessedColumnSeq builds a sequence column descriptor.
// Occupy range 0 to 20 (inclusive) since logSizes range from 4 to 24.
func NewPreprocessedColumnSeq(api frontend.API, logSize frontend.Variable) PreprocessedColumn {
	id := api.Sub(logSize, frontend.Variable(4))
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnPedersenPoints builds a pedersen points column descriptor.
// Occupy range 21 to 76 (inclusive) since pedersen points range from 0 to 55.
func NewPreprocessedColumnPedersenPoints(api frontend.API, index frontend.Variable) PreprocessedColumn {
	id := api.Add(index, frontend.Variable(21))
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnBitwiseXor builds a bitwise xor column descriptor.
// Occupy range 77 to 91 (inclusive)
func NewPreprocessedColumnBitwiseXor(api frontend.API, nBits, columnID frontend.Variable) PreprocessedColumn {
	// nTermBits is either 4, 7, 8, 9, or 10
	// convert to id in range 0 to 4
	is4 := cmp.IsEqual(api, nBits, frontend.Variable(4))
	is7 := cmp.IsEqual(api, nBits, frontend.Variable(7))
	is8 := cmp.IsEqual(api, nBits, frontend.Variable(8))
	is9 := cmp.IsEqual(api, nBits, frontend.Variable(9))
	is10 := cmp.IsEqual(api, nBits, frontend.Variable(10))
	nBitsID := api.Select(is4,
		frontend.Variable(0),
		api.Select(is7,
			frontend.Variable(1),
			api.Select(is8,
				frontend.Variable(2),
				api.Select(is9,
					frontend.Variable(3),
					api.Select(is10,
						frontend.Variable(4),
						frontend.Variable(0),
					),
				),
			),
		),
	)
	base := frontend.Variable(77)
	step := frontend.Variable(3)
	// id = 77 + 3 * nBitsID + columnID
	id := api.Add(api.Add(base, api.Mul(nBitsID, step)), columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck2 builds a range-check (2 values) column descriptor.
// Occupy range 92 to 99 (inclusive)
func NewPreprocessedColumnRangeCheck2(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	// values are either 9_9, 5_4, 4_4 or 4_3
	is99 := cmp.IsEqual(api, values[0], frontend.Variable(9))
	is54 := cmp.IsEqual(api, values[0], frontend.Variable(5))
	is44 := cmp.IsEqual(api, values[0], frontend.Variable(4))
	is43 := cmp.IsEqual(api, values[1], frontend.Variable(3))
	valuesID := api.Select(is99,
		frontend.Variable(0),
		api.Select(is54,
			frontend.Variable(1),
			api.Select(is44,
				frontend.Variable(2),
				api.Select(is43,
					frontend.Variable(3),
					frontend.Variable(0),
				),
			),
		),
	)
	base := frontend.Variable(92)
	step := frontend.Variable(2)
	// id = 92 + 2 * valuesID + columnID
	id := api.Add(api.Add(base, api.Mul(valuesID, step)), columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck3 builds a range-check (3 values) column descriptor.
// Occupy range 100 to 102 (inclusive)
func NewPreprocessedColumnRangeCheck3(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	base := frontend.Variable(100)
	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck4 builds a range-check (4 values) column descriptor.
// Occupy range 103 to 110 (inclusive)
func NewPreprocessedColumnRangeCheck4(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	// values are either 3_6_6_3, 4_4_4_4
	is3663 := cmp.IsEqual(api, values[0], frontend.Variable(3))
	is4444 := cmp.IsEqual(api, values[0], frontend.Variable(4))
	valuesID := api.Select(is3663,
		frontend.Variable(0),
		api.Select(is4444,
			frontend.Variable(1),
			frontend.Variable(0),
		),
	)
	base := frontend.Variable(103)
	step := frontend.Variable(4)
	id := api.Add(api.Add(base, api.Mul(valuesID, step)), columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnRangeCheck5 builds a range-check (5 values) column descriptor.
// Occupy range 111 to 115 (inclusive)
func NewPreprocessedColumnRangeCheck5(api frontend.API, values []frontend.Variable, columnID frontend.Variable) PreprocessedColumn {
	base := frontend.Variable(111)
	id := api.Add(base, columnID)
	return PreprocessedColumn{
		id: id,
	}
}

// NewPreprocessedColumnPoseidonRoundKeys builds a poseidon round keys column descriptor.
// Occupy range 116 to 145 (inclusive)
func NewPreprocessedColumnPoseidonRoundKeys(api frontend.API, index frontend.Variable) PreprocessedColumn {
	base := frontend.Variable(116)
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

// PreprocessedSampledValues offers lookup helpers mirroring the Cairo implementation.
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

// Get returns the sampled value for the provided column, panicking if it is absent.
func (ps PreprocessedSampledValues) Get(column PreprocessedColumn) m31.QM31 {
	key := column.Key()
	encodedValue := ps.values.Lookup(key)[0]
	value := ps.qm31.DecodeNative(encodedValue)
	return value
}

// ╔══════════════════════════════════╗
// ║    Preprocessed Columns Const    ║
// ╚══════════════════════════════════╝

// PreprocessedColumns defines the ordering shared with the Cairo implementation.
// var PreprocessedColumns = []PreprocessedColumn{
// 	NewPreprocessedColumnSeq(frontend.Variable(24)),
// 	NewPreprocessedColumnSeq(frontend.Variable(23)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(0)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(1)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(2)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(3)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(4)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(5)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(6)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(7)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(8)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(9)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(10)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(11)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(12)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(13)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(14)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(15)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(16)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(17)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(18)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(19)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(20)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(21)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(22)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(23)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(24)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(25)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(26)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(27)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(28)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(29)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(30)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(31)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(32)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(33)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(34)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(35)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(36)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(37)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(38)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(39)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(40)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(41)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(42)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(43)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(44)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(45)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(46)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(47)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(48)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(49)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(50)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(51)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(52)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(53)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(54)),
// 	NewPreprocessedColumnPedersenPoints(frontend.Variable(55)),
// 	NewPreprocessedColumnSeq(frontend.Variable(22)),
// 	NewPreprocessedColumnSeq(frontend.Variable(21)),
// 	NewPreprocessedColumnSeq(frontend.Variable(20)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(0)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(1)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(2)),
// 	NewPreprocessedColumnSeq(frontend.Variable(19)),
// 	NewPreprocessedColumnSeq(frontend.Variable(18)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(0)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(1)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(9), frontend.Variable(9)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(9), frontend.Variable(9)}, frontend.Variable(1)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(1)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(3)),
// 	NewPreprocessedColumnSeq(frontend.Variable(17)),
// 	NewPreprocessedColumnSeq(frontend.Variable(16)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(0)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(1)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(1)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(3)),
// 	NewPreprocessedColumnSeq(frontend.Variable(15)),
// 	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(1)),
// 	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(3)),
// 	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(4)),
// 	NewPreprocessedColumnSeq(frontend.Variable(14)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(0)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(1)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(1)),
// 	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(2)),
// 	NewPreprocessedColumnSeq(frontend.Variable(13)),
// 	NewPreprocessedColumnSeq(frontend.Variable(12)),
// 	NewPreprocessedColumnSeq(frontend.Variable(11)),
// 	NewPreprocessedColumnSeq(frontend.Variable(10)),
// 	NewPreprocessedColumnSeq(frontend.Variable(9)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(5), frontend.Variable(4)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(5), frontend.Variable(4)}, frontend.Variable(1)),
// 	NewPreprocessedColumnSeq(frontend.Variable(8)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(0)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(1)),
// 	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(2)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(1)),
// 	NewPreprocessedColumnSeq(frontend.Variable(7)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(3)}, frontend.Variable(0)),
// 	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(3)}, frontend.Variable(1)),
// 	NewPreprocessedColumnSeq(frontend.Variable(6)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(0)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(1)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(2)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(3)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(4)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(5)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(6)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(7)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(8)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(9)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(10)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(11)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(12)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(13)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(14)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(15)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(16)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(17)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(18)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(19)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(20)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(21)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(22)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(23)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(24)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(25)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(26)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(27)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(28)),
// 	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(29)),
// 	NewPreprocessedColumnSeq(frontend.Variable(5)),
// 	NewPreprocessedColumnSeq(frontend.Variable(4)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(0)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(1)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(2)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(3)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(4)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(5)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(6)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(7)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(8)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(9)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(10)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(11)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(12)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(13)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(14)),
// 	NewPreprocessedColumnBlakeSigma(frontend.Variable(15)),
// }

// PreprocessedLogSizes returns the log size of each canonical preprocessed column.
func PreprocessedLogSizes() []frontend.Variable {
	return []frontend.Variable{
		frontend.Variable(24),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(23),
		frontend.Variable(22),
		frontend.Variable(21),
		frontend.Variable(20),
		frontend.Variable(20),
		frontend.Variable(20),
		frontend.Variable(20),
		frontend.Variable(19),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(18),
		frontend.Variable(17),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(16),
		frontend.Variable(15),
		frontend.Variable(15),
		frontend.Variable(15),
		frontend.Variable(15),
		frontend.Variable(15),
		frontend.Variable(15),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(14),
		frontend.Variable(13),
		frontend.Variable(12),
		frontend.Variable(11),
		frontend.Variable(10),
		frontend.Variable(9),
		frontend.Variable(9),
		frontend.Variable(9),
		frontend.Variable(8),
		frontend.Variable(8),
		frontend.Variable(8),
		frontend.Variable(8),
		frontend.Variable(8),
		frontend.Variable(8),
		frontend.Variable(7),
		frontend.Variable(7),
		frontend.Variable(7),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(5),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
	}
}
