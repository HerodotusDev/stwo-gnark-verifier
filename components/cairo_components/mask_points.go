package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// TODO: this file structure mirrors the TreeMaskPoints structure, should be merged into a single structure.

// TreeMaskPoints contains the sample points for each tree.
type TreeMaskPoints [][][]circle.Point

// NewTreeMaskPoints builds a TreeMaskPoints entry from the provided point.
func NewTreeMaskPoints(point, pointNegOne circle.Point, traceCols, interactionCols int) TreeMaskPoints {
	maskPoints := make(TreeMaskPoints, N_TREES)
	for i := range maskPoints {
		maskPoints[i] = make([][]circle.Point, 0)
	}
	if traceCols > 0 {
		maskPoints[MAIN_IDX] = appendRepeatMaskPoints(maskPoints[MAIN_IDX], []circle.Point{point}, traceCols)
	}
	if interactionCols > 0 {
		maskPoints[INTERACTION_IDX] = appendRepeatMaskPoints(maskPoints[INTERACTION_IDX], []circle.Point{point}, interactionCols-4)
		maskPoints[INTERACTION_IDX] = appendRepeatMaskPoints(maskPoints[INTERACTION_IDX], []circle.Point{pointNegOne, point}, 4)
	}
	return maskPoints
}

// ConcatTreeMaskPoints concatenates the columns of multiple TreeMaskPoints.
func ConcatTreeMaskPoints(trees ...TreeMaskPoints) TreeMaskPoints {
	result := make(TreeMaskPoints, N_TREES)
	for i := range result {
		result[i] = make([][]circle.Point, 0)
	}
	for _, maskPoints := range trees {
		if maskPoints == nil {
			continue
		}
		for idx := 0; idx < len(maskPoints); idx++ {
			result[idx] = append(result[idx], maskPoints[idx]...)
		}
	}
	return result
}

func appendRepeatMaskPoints(base [][]circle.Point, value []circle.Point, count int) [][]circle.Point {
	if count <= 0 {
		return base
	}
	for i := 0; i < count; i++ {
		base = append(base, value)
	}
	return base
}

func oodsPointNegOne(oodsPoint circle.Point, circleChip *circle.CircleChip, logSize uint32) circle.Point {
	traceGenPoint := circle.NewCanonicCoset(circleChip, logSize).Coset().Step().Point()
	traceGenPointNegOne := circleChip.BaseNeg(traceGenPoint)
	return circleChip.AddBasePoint(oodsPoint, traceGenPointNegOne)
}

// ╔══════════════════════════════════╗
// ║            Opcodes               ║
// ╚══════════════════════════════════╝

func (claim AddOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addOpcodeTraceColumns, addOpcodeInteractionColumns)
}

func (claim AddApOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addApOpcodeTraceColumns, addApOpcodeInteractionColumns)
}

func (claim AddSmallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addSmallOpcodeTraceColumns, addSmallOpcodeInteractionColumns)
}

func (claim AssertEqOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqOpcodeTraceColumns, assertEqOpcodeInteractionColumns)
}

func (claim AssertEqDoubleDerefOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqDoubleDerefOpcodeTraceColumns, assertEqDoubleDerefOpcodeInteractionColumns)
}

func (claim AssertEqImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqImmOpcodeTraceColumns, assertEqImmOpcodeInteractionColumns)
}

func (claim BlakeCompressOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeCompressTraceColumns, blakeCompressInteractionColumns)
}

func (claim CallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, callOpcodeTraceColumns, callOpcodeInteractionColumns)
}

func (claim CallRelImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, callRelImmOpcodeTraceColumns, callRelImmOpcodeInteractionColumns)
}

func (claim GenericOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, genericOpcodeTraceColumns, genericOpcodeInteractionColumns)
}

func (claim JnzOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jnzOpcodeTraceColumns, jnzOpcodeInteractionColumns)
}

func (claim JnzTakenOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jnzTakenOpcodeTraceColumns, jnzTakenOpcodeInteractionColumns)
}

func (claim JumpOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpOpcodeTraceColumns, jumpOpcodeInteractionColumns)
}

func (claim JumpDoubleDerefOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpDoubleDerefOpcodeTraceColumns, jumpDoubleDerefOpcodeInteractionColumns)
}

func (claim JumpRelOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpRelOpcodeTraceColumns, jumpRelOpcodeInteractionColumns)
}

func (claim JumpRelImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpRelImmOpcodeTraceColumns, jumpRelImmOpcodeInteractionColumns)
}

func (claim MulOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulOpcodeTraceColumns, mulOpcodeInteractionColumns)
}

func (claim MulSmallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulSmallOpcodeTraceColumns, mulSmallOpcodeInteractionColumns)
}

func (claim Qm31OpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, qm31OpcodeTraceColumns, qm31OpcodeInteractionColumns)
}

func (claim RetOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, retOpcodeTraceColumns, retOpcodeInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Builtins              ║
// ╚══════════════════════════════════╝

func (claim AddModBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addModBuiltinTraceColumns, addModBuiltinInteractionColumns)
}

func (claim BitwiseBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, bitwiseBuiltinTraceColumns, bitwiseBuiltinInteractionColumns)
}

func (claim MulModBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulModBuiltinTraceColumns, mulModBuiltinInteractionColumns)
}

func (claim PedersenBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, pedersenBuiltinTraceColumns, pedersenBuiltinInteractionColumns)
}

func (claim PoseidonBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidonBuiltinTraceColumns, poseidonBuiltinInteractionColumns)
}

func (claim RangeCheck96BuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheck96BuiltinTraceColumns, rangeCheck96BuiltinInteractionColumns)
}

func (claim RangeCheck128BuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheck128BuiltinTraceColumns, rangeCheck128BuiltinInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║               Blake              ║
// ╚══════════════════════════════════╝

func (claim BlakeRoundClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeRoundTraceColumns, blakeRoundInteractionColumns)
}

func (claim BlakeGClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeGTraceColumns, blakeGInteractionColumns)
}

func (claim BlakeRoundSigmaClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(blakeRoundSigmaLogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	for i := 0; i < 16; i++ {
		k := NewPreprocessedColumnBlakeSigma(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, blakeRoundSigmaLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)
}

func (claim TripleXor32Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, tripleXor32TraceColumns, tripleXor32InteractionColumns)
}

func (claim VerifyBitwiseXor12Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, verifyBitwiseXor12LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, VerifyBitwiseXor12TraceColumns, VerifyBitwiseXor12InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Pedersen              ║
// ╚══════════════════════════════════╝

func (claim PartialEcMulClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, partialEcMulTraceColumns, partialEcMulInteractionColumns)
}

func (PedersenPointsTableClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(pedersenPointsTableLogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	for i := 0; i < pedersenPointsTableColumns; i++ {
		k := NewPreprocessedColumnPedersenPoints(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, pedersenPointsTableLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Poseidon              ║
// ╚══════════════════════════════════╝

func (claim Poseidon3PartialRoundsChainClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidon3PartialRoundsTraceColumns, poseidon3PartialRoundsInteractionColumns)
}

func (claim PoseidonFullRoundChainClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidonFullRoundTraceColumns, poseidonFullRoundInteractionColumns)
}

func (claim Cube252Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, cube252TraceColumns, cube252InteractionColumns)
}

func (PoseidonRoundKeysClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(uint8(poseidonRoundKeysLogSize)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	for i := 0; i < poseidonRoundKeysColumns; i++ {
		k := NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, poseidonRoundKeysLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)
}

func (claim RangeCheckFelt252Width27Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheckFelt252Width27TraceColumns, rangeCheckFelt252Width27InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Memory/Lookup          ║
// ╚══════════════════════════════════╝

func (claim MemoryAddressToIdClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryAddressToIdTraceColumns, memoryAddressToIdInteractionColumns)
}

func (claim MemoryIdToBigBigClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryIdToBigBigTraceCols, memoryIdToBigBigInteractionColumns)
}

func (claim MemoryIdToBigSmallClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryIdToBigSmallTraceCols, memoryIdToBigSmallInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyInstruction        ║
// ╚══════════════════════════════════╝

func (claim VerifyInstructionClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, verifyInstructionTraceColumns, verifyInstructionInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyBitwiseXor         ║
// ╚══════════════════════════════════╝

func (claim VerifyBitwiseXor4Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, verifyBitwiseXor4LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor7Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, verifyBitwiseXor7LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor8Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, verifyBitwiseXor8LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor9Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, verifyBitwiseXor9LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Range Check           ║
// ╚══════════════════════════════════╝

func (claim RangeCheck3_3_3_3_3Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
	}
	k := NewPreprocessedColumnRangeCheck5(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, uints.NewU8(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, uints.NewU8(4)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck3_3_3_3_3LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck3_6_6_3Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(6),
		uints.NewU8(6),
		uints.NewU8(3),
	}
	k := NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck3_6_6_3LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck4_3Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(3),
	}
	k := NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck4_3LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck4_4Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(4),
	}
	k := NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck4_4LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck4_4_4_4Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
	}
	k := NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck4_4_4_4LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck5_4Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(5),
		uints.NewU8(4),
	}
	k := NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck5_4LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck6Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(rangeCheck6LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck6LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck7_2_5Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(7),
		uints.NewU8(2),
		uints.NewU8(5),
	}
	k := NewPreprocessedColumnRangeCheck3(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck3(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck3(values, uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck7_2_5LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck8Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(uints.NewU8(8)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck8LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck9_9Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []uints.U8{
		uints.NewU8(9),
		uints.NewU8(9),
	}
	k := NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck9_9LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck11Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(rangeCheck11LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck11LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck12Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(rangeCheck12LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck12LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck18Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(rangeCheck18LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck18LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck19Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := sequencePreprocessedColumn(rangeCheck19LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, rangeCheck19LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}
