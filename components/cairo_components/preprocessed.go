package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var (
	preprocessedColumnBitwiseXor        = frontend.Variable(0)
	preprocessedColumnSeq               = frontend.Variable(1)
	preprocessedColumnRangeCheck2       = frontend.Variable(2)
	preprocessedColumnRangeCheck3       = frontend.Variable(3)
	preprocessedColumnRangeCheck4       = frontend.Variable(4)
	preprocessedColumnRangeCheck5       = frontend.Variable(5)
	preprocessedColumnPoseidonRoundKeys = frontend.Variable(6)
	preprocessedColumnBlakeSigma        = frontend.Variable(7)
	preprocessedColumnPedersenPoints    = frontend.Variable(8)
)

// ╔══════════════════════════════════╗
// ║       Preprocessed Columns       ║
// ╚══════════════════════════════════╝

// PreprocessedColumn mimics the Cairo enum variants used to index preprocessed mask values.
type PreprocessedColumn struct {
	kind              frontend.Variable   // kind of the preprocessed column encoded as a 8bit value
	seqLogSize        frontend.Variable   // log size of the sequence
	nTermBits         frontend.Variable   // number of bits in the term
	term              frontend.Variable   // { 0 = left operand, 1 = right operand, 2 = xor result }
	rangeCheckValues  []frontend.Variable // number of bits per range checked value
	rangeCheckIndex   frontend.Variable   // index of the RC column
	simpleColumnIndex frontend.Variable   // round constants for hashes
}

// NewPreprocessedColumnSeq builds a sequence column descriptor.
func NewPreprocessedColumnSeq(logSize frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:       preprocessedColumnSeq,
		seqLogSize: logSize,
	}
}

// NewPreprocessedColumnPedersenPoints builds a pedersen points column descriptor.
func NewPreprocessedColumnPedersenPoints(index frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:              preprocessedColumnPedersenPoints,
		simpleColumnIndex: index,
	}
}

// NewPreprocessedColumnBitwiseXor builds a bitwise xor column descriptor.
func NewPreprocessedColumnBitwiseXor(nTermBits, term frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:      preprocessedColumnBitwiseXor,
		nTermBits: nTermBits,
		term:      term,
	}
}

// NewPreprocessedColumnRangeCheck2 builds a range-check (2 values) column descriptor.
func NewPreprocessedColumnRangeCheck2(values []frontend.Variable, columnIndex frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck2,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck3 builds a range-check (3 values) column descriptor.
func NewPreprocessedColumnRangeCheck3(values []frontend.Variable, columnIndex frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck3,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck4 builds a range-check (4 values) column descriptor.
func NewPreprocessedColumnRangeCheck4(values []frontend.Variable, columnIndex frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck4,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck5 builds a range-check (5 values) column descriptor.
func NewPreprocessedColumnRangeCheck5(values []frontend.Variable, columnIndex frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck5,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnPoseidonRoundKeys builds a poseidon round keys column descriptor.
func NewPreprocessedColumnPoseidonRoundKeys(index frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:              preprocessedColumnPoseidonRoundKeys,
		simpleColumnIndex: index,
	}
}

// NewPreprocessedColumnBlakeSigma builds a blake sigma column descriptor.
func NewPreprocessedColumnBlakeSigma(index frontend.Variable) PreprocessedColumn {
	return PreprocessedColumn{
		kind:              preprocessedColumnBlakeSigma,
		simpleColumnIndex: index,
	}
}

// Key encodes the column using the same packing logic as the Cairo PreprocessedColumnKey.
func (column PreprocessedColumn) Key(api frontend.API) uints.U64 {
	return column.encode(api)
}

// encode encodes a PreprocessedColumn as a 64-bit value.
func (column PreprocessedColumn) encode(api frontend.API) uints.U64 {
	uapi64, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}
	var res uints.U64

	switch column.kind {
	case preprocessedColumnBitwiseXor:
		res = uapi64.PackLSB(bapi.ValueOf(column.kind), bapi.ValueOf(column.nTermBits), bapi.ValueOf(column.term))
	case preprocessedColumnSeq:
		res = uapi64.PackLSB(bapi.ValueOf(column.kind), bapi.ValueOf(column.seqLogSize))
	case preprocessedColumnRangeCheck2:
		res = column.rangeCheckEncode(uapi64, bapi)
	case preprocessedColumnRangeCheck3:
		res = column.rangeCheckEncode(uapi64, bapi)
	case preprocessedColumnRangeCheck4:
		res = column.rangeCheckEncode(uapi64, bapi)
	case preprocessedColumnRangeCheck5:
		res = column.rangeCheckEncode(uapi64, bapi)
	case preprocessedColumnPoseidonRoundKeys:
		res = uapi64.PackLSB(bapi.ValueOf(column.kind), bapi.ValueOf(column.simpleColumnIndex))
	case preprocessedColumnBlakeSigma:
		res = uapi64.PackLSB(bapi.ValueOf(column.kind), bapi.ValueOf(column.simpleColumnIndex))
	case preprocessedColumnPedersenPoints:
		res = uapi64.PackLSB(bapi.ValueOf(column.kind), bapi.ValueOf(column.simpleColumnIndex))
	default:
		panic("unsupported preprocessed column kind")
	}

	return res
}

// rangeCheckEncode encodes a range-check column as a 64-bit value.
func (column PreprocessedColumn) rangeCheckEncode(uapi64 *uints.BinaryField[uints.U64], bapi *uints.Bytes) uints.U64 {
	args := []frontend.Variable{column.kind}
	args = append(args, column.rangeCheckValues...)
	args = append(args, column.rangeCheckIndex)
	bytes := make([]uints.U8, len(args))
	for i, arg := range args {
		bytes[i] = bapi.ValueOf(arg)
	}
	res := uapi64.PackLSB(bytes...)
	return res
}

// ╔══════════════════════════════════╗
// ║    Preprocessed Sampled Values   ║
// ╚══════════════════════════════════╝

// PreprocessedSampledValues offers lookup helpers mirroring the Cairo implementation.
type PreprocessedSampledValues struct {
	api frontend.API
	m31 *m31.M31Chip

	values map[uints.U64]m31.QM31
}

// NewPreprocessedSampledValues builds a PreprocessedSampledValues from a slice of sampled values.
func NewPreprocessedSampledValues(api frontend.API, m31Chip *m31.M31Chip, preprocessedSampledValuesRaw [][]m31.QM31) PreprocessedSampledValues {
	values := make(map[uints.U64]m31.QM31, len(PreprocessedColumns))

	for i, column := range PreprocessedColumns {
		columnValues := preprocessedSampledValuesRaw[i]
		switch len(columnValues) {
		case 0:
			continue
		case 1:
			values[column.Key(api)] = columnValues[0]
		default:
			panic("preprocessed column has more than 1 sampled value")
		}
	}

	return PreprocessedSampledValues{
		api:    api,
		m31:    m31Chip,
		values: values,
	}
}

// Get returns the sampled value for the provided column, panicking if it is absent.
func (ps PreprocessedSampledValues) Get(column PreprocessedColumn) m31.QM31 {
	if len(ps.values) == 0 {
		panic("preprocessed column map is empty")
	}
	key := column.Key(ps.api)
	value, ok := ps.values[key]
	if !ok {
		panic("preprocessed column not found")
	}
	return value
}

// ╔══════════════════════════════════╗
// ║    Preprocessed Columns Const    ║
// ╚══════════════════════════════════╝

// PreprocessedColumns defines the ordering shared with the Cairo implementation.
var PreprocessedColumns = []PreprocessedColumn{
	NewPreprocessedColumnSeq(frontend.Variable(24)),
	NewPreprocessedColumnSeq(frontend.Variable(23)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(0)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(1)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(2)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(3)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(4)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(5)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(6)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(7)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(8)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(9)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(10)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(11)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(12)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(13)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(14)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(15)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(16)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(17)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(18)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(19)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(20)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(21)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(22)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(23)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(24)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(25)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(26)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(27)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(28)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(29)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(30)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(31)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(32)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(33)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(34)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(35)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(36)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(37)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(38)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(39)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(40)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(41)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(42)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(43)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(44)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(45)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(46)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(47)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(48)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(49)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(50)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(51)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(52)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(53)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(54)),
	NewPreprocessedColumnPedersenPoints(frontend.Variable(55)),
	NewPreprocessedColumnSeq(frontend.Variable(22)),
	NewPreprocessedColumnSeq(frontend.Variable(21)),
	NewPreprocessedColumnSeq(frontend.Variable(20)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(0)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(1)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(10), frontend.Variable(2)),
	NewPreprocessedColumnSeq(frontend.Variable(19)),
	NewPreprocessedColumnSeq(frontend.Variable(18)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(0)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(1)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(9), frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(9), frontend.Variable(9)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(9), frontend.Variable(9)}, frontend.Variable(1)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(1)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(3), frontend.Variable(6), frontend.Variable(6), frontend.Variable(3)}, frontend.Variable(3)),
	NewPreprocessedColumnSeq(frontend.Variable(17)),
	NewPreprocessedColumnSeq(frontend.Variable(16)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(0)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(1)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(8), frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(1)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck4([]frontend.Variable{frontend.Variable(4), frontend.Variable(4), frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(3)),
	NewPreprocessedColumnSeq(frontend.Variable(15)),
	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(1)),
	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(3)),
	NewPreprocessedColumnRangeCheck5([]frontend.Variable{frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3), frontend.Variable(3)}, frontend.Variable(4)),
	NewPreprocessedColumnSeq(frontend.Variable(14)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(0)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(1)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(7), frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(1)),
	NewPreprocessedColumnRangeCheck3([]frontend.Variable{frontend.Variable(7), frontend.Variable(2), frontend.Variable(5)}, frontend.Variable(2)),
	NewPreprocessedColumnSeq(frontend.Variable(13)),
	NewPreprocessedColumnSeq(frontend.Variable(12)),
	NewPreprocessedColumnSeq(frontend.Variable(11)),
	NewPreprocessedColumnSeq(frontend.Variable(10)),
	NewPreprocessedColumnSeq(frontend.Variable(9)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(5), frontend.Variable(4)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(5), frontend.Variable(4)}, frontend.Variable(1)),
	NewPreprocessedColumnSeq(frontend.Variable(8)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(0)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(1)),
	NewPreprocessedColumnBitwiseXor(frontend.Variable(4), frontend.Variable(2)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(4)}, frontend.Variable(1)),
	NewPreprocessedColumnSeq(frontend.Variable(7)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(3)}, frontend.Variable(0)),
	NewPreprocessedColumnRangeCheck2([]frontend.Variable{frontend.Variable(4), frontend.Variable(3)}, frontend.Variable(1)),
	NewPreprocessedColumnSeq(frontend.Variable(6)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(0)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(1)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(2)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(3)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(4)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(5)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(6)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(7)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(8)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(9)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(10)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(11)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(12)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(13)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(14)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(15)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(16)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(17)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(18)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(19)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(20)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(21)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(22)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(23)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(24)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(25)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(26)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(27)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(28)),
	NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(29)),
	NewPreprocessedColumnSeq(frontend.Variable(5)),
	NewPreprocessedColumnSeq(frontend.Variable(4)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(0)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(1)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(2)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(3)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(4)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(5)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(6)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(7)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(8)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(9)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(10)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(11)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(12)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(13)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(14)),
	NewPreprocessedColumnBlakeSigma(frontend.Variable(15)),
}

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
