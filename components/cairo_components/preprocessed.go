package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var (
	preprocessedColumnBitwiseXor        = uints.NewU8(0)
	preprocessedColumnSeq               = uints.NewU8(1)
	preprocessedColumnRangeCheck2       = uints.NewU8(2)
	preprocessedColumnRangeCheck3       = uints.NewU8(3)
	preprocessedColumnRangeCheck4       = uints.NewU8(4)
	preprocessedColumnRangeCheck5       = uints.NewU8(5)
	preprocessedColumnPoseidonRoundKeys = uints.NewU8(6)
	preprocessedColumnBlakeSigma        = uints.NewU8(7)
	preprocessedColumnPedersenPoints    = uints.NewU8(8)
)

// ╔══════════════════════════════════╗
// ║       Preprocessed Columns       ║
// ╚══════════════════════════════════╝

// PreprocessedColumn mimics the Cairo enum variants used to index preprocessed mask values.
type PreprocessedColumn struct {
	kind              uints.U8   // kind of the preprocessed column encoded as a 8bit value
	seqLogSize        uints.U8   // log size of the sequence
	nTermBits         uints.U8   // number of bits in the term
	term              uints.U8   // { 0 = left operand, 1 = right operand, 2 = xor result }
	rangeCheckValues  []uints.U8 // number of bits per range checked value
	rangeCheckIndex   uints.U8   // index of the RC column
	simpleColumnIndex uints.U8   // round constants for hashes
}

// NewPreprocessedColumnSeq builds a sequence column descriptor.
func NewPreprocessedColumnSeq(logSize uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:       preprocessedColumnSeq,
		seqLogSize: logSize,
	}
}

// NewPreprocessedColumnPedersenPoints builds a pedersen points column descriptor.
func NewPreprocessedColumnPedersenPoints(index uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:              preprocessedColumnPedersenPoints,
		simpleColumnIndex: index,
	}
}

// NewPreprocessedColumnBitwiseXor builds a bitwise xor column descriptor.
func NewPreprocessedColumnBitwiseXor(nTermBits, term uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:      preprocessedColumnBitwiseXor,
		nTermBits: nTermBits,
		term:      term,
	}
}

// NewPreprocessedColumnRangeCheck2 builds a range-check (2 values) column descriptor.
func NewPreprocessedColumnRangeCheck2(values []uints.U8, columnIndex uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck2,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck3 builds a range-check (3 values) column descriptor.
func NewPreprocessedColumnRangeCheck3(values []uints.U8, columnIndex uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck3,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck4 builds a range-check (4 values) column descriptor.
func NewPreprocessedColumnRangeCheck4(values []uints.U8, columnIndex uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck4,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnRangeCheck5 builds a range-check (5 values) column descriptor.
func NewPreprocessedColumnRangeCheck5(values []uints.U8, columnIndex uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:             preprocessedColumnRangeCheck5,
		rangeCheckValues: values,
		rangeCheckIndex:  columnIndex,
	}
}

// NewPreprocessedColumnPoseidonRoundKeys builds a poseidon round keys column descriptor.
func NewPreprocessedColumnPoseidonRoundKeys(index uints.U8) PreprocessedColumn {
	return PreprocessedColumn{
		kind:              preprocessedColumnPoseidonRoundKeys,
		simpleColumnIndex: index,
	}
}

// NewPreprocessedColumnBlakeSigma builds a blake sigma column descriptor.
func NewPreprocessedColumnBlakeSigma(index uints.U8) PreprocessedColumn {
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
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	var res uints.U64

	switch column.kind {
	case preprocessedColumnBitwiseXor:
		res = uapi.PackLSB(column.kind, column.nTermBits, column.term)
	case preprocessedColumnSeq:
		res = uapi.PackLSB(column.kind, column.seqLogSize)
	case preprocessedColumnRangeCheck2:
		res = column.rangeCheckEncode(uapi)
	case preprocessedColumnRangeCheck3:
		res = column.rangeCheckEncode(uapi)
	case preprocessedColumnRangeCheck4:
		res = column.rangeCheckEncode(uapi)
	case preprocessedColumnRangeCheck5:
		res = column.rangeCheckEncode(uapi)
	case preprocessedColumnPoseidonRoundKeys:
		res = uapi.PackLSB(column.kind, column.simpleColumnIndex)
	case preprocessedColumnBlakeSigma:
		res = uapi.PackLSB(column.kind, column.simpleColumnIndex)
	case preprocessedColumnPedersenPoints:
		res = uapi.PackLSB(column.kind, column.simpleColumnIndex)
	default:
		panic("unsupported preprocessed column kind")
	}

	return res
}

// rangeCheckEncode encodes a range-check column as a 64-bit value.
func (column PreprocessedColumn) rangeCheckEncode(uapi *uints.BinaryField[uints.U64]) uints.U64 {
	args := []uints.U8{column.kind}
	args = append(args, column.rangeCheckValues...)
	args = append(args, column.rangeCheckIndex)
	res := uapi.PackLSB(args...)
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
	NewPreprocessedColumnSeq(uints.NewU8(24)),
	NewPreprocessedColumnSeq(uints.NewU8(23)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(0)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(1)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(2)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(3)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(4)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(5)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(6)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(7)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(8)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(9)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(10)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(11)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(12)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(13)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(14)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(15)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(16)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(17)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(18)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(19)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(20)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(21)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(22)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(23)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(24)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(25)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(26)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(27)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(28)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(29)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(30)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(31)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(32)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(33)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(34)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(35)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(36)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(37)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(38)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(39)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(40)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(41)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(42)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(43)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(44)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(45)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(46)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(47)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(48)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(49)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(50)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(51)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(52)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(53)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(54)),
	NewPreprocessedColumnPedersenPoints(uints.NewU8(55)),
	NewPreprocessedColumnSeq(uints.NewU8(22)),
	NewPreprocessedColumnSeq(uints.NewU8(21)),
	NewPreprocessedColumnSeq(uints.NewU8(20)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(0)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(1)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(2)),
	NewPreprocessedColumnSeq(uints.NewU8(19)),
	NewPreprocessedColumnSeq(uints.NewU8(18)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(0)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(1)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(9), uints.NewU8(9)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(9), uints.NewU8(9)}, uints.NewU8(1)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(3), uints.NewU8(6), uints.NewU8(6), uints.NewU8(3)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(3), uints.NewU8(6), uints.NewU8(6), uints.NewU8(3)}, uints.NewU8(1)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(3), uints.NewU8(6), uints.NewU8(6), uints.NewU8(3)}, uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(3), uints.NewU8(6), uints.NewU8(6), uints.NewU8(3)}, uints.NewU8(3)),
	NewPreprocessedColumnSeq(uints.NewU8(17)),
	NewPreprocessedColumnSeq(uints.NewU8(16)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(0)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(1)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(4), uints.NewU8(4), uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(4), uints.NewU8(4), uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(1)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(4), uints.NewU8(4), uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck4([]uints.U8{uints.NewU8(4), uints.NewU8(4), uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(3)),
	NewPreprocessedColumnSeq(uints.NewU8(15)),
	NewPreprocessedColumnRangeCheck5([]uints.U8{uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck5([]uints.U8{uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3)}, uints.NewU8(1)),
	NewPreprocessedColumnRangeCheck5([]uints.U8{uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3)}, uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck5([]uints.U8{uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3)}, uints.NewU8(3)),
	NewPreprocessedColumnRangeCheck5([]uints.U8{uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3), uints.NewU8(3)}, uints.NewU8(4)),
	NewPreprocessedColumnSeq(uints.NewU8(14)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(0)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(1)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck3([]uints.U8{uints.NewU8(7), uints.NewU8(2), uints.NewU8(5)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck3([]uints.U8{uints.NewU8(7), uints.NewU8(2), uints.NewU8(5)}, uints.NewU8(1)),
	NewPreprocessedColumnRangeCheck3([]uints.U8{uints.NewU8(7), uints.NewU8(2), uints.NewU8(5)}, uints.NewU8(2)),
	NewPreprocessedColumnSeq(uints.NewU8(13)),
	NewPreprocessedColumnSeq(uints.NewU8(12)),
	NewPreprocessedColumnSeq(uints.NewU8(11)),
	NewPreprocessedColumnSeq(uints.NewU8(10)),
	NewPreprocessedColumnSeq(uints.NewU8(9)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(5), uints.NewU8(4)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(5), uints.NewU8(4)}, uints.NewU8(1)),
	NewPreprocessedColumnSeq(uints.NewU8(8)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(0)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(1)),
	NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(2)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(4), uints.NewU8(4)}, uints.NewU8(1)),
	NewPreprocessedColumnSeq(uints.NewU8(7)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(4), uints.NewU8(3)}, uints.NewU8(0)),
	NewPreprocessedColumnRangeCheck2([]uints.U8{uints.NewU8(4), uints.NewU8(3)}, uints.NewU8(1)),
	NewPreprocessedColumnSeq(uints.NewU8(6)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(0)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(1)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(2)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(3)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(4)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(5)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(6)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(7)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(8)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(9)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(10)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(11)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(12)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(13)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(14)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(15)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(16)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(17)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(18)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(19)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(20)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(21)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(22)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(23)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(24)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(25)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(26)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(27)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(28)),
	NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(29)),
	NewPreprocessedColumnSeq(uints.NewU8(5)),
	NewPreprocessedColumnSeq(uints.NewU8(4)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(0)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(1)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(2)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(3)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(4)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(5)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(6)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(7)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(8)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(9)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(10)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(11)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(12)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(13)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(14)),
	NewPreprocessedColumnBlakeSigma(uints.NewU8(15)),
}
