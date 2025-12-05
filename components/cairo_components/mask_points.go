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

func oodsPointNegOne(oodsPoint circle.Point, circleChip *circle.CircleChip, logSize frontend.Variable) circle.Point {
	traceGenPoint := circle.NewCanonicCoset(circleChip, logSize).Coset().Step().Point()
	traceGenPointNegOne := circleChip.BaseNeg(traceGenPoint)
	return circleChip.AddBasePoint(oodsPoint, traceGenPointNegOne)
}

// ╔══════════════════════════════════╗
// ║            Opcodes               ║
// ╚══════════════════════════════════╝

func (claim AddOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AddOpcodeTraceColumns, AddOpcodeInteractionColumns)
}

func (claim AddApOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AddApOpcodeTraceColumns, AddApOpcodeInteractionColumns)
}

func (claim AddSmallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AddSmallOpcodeTraceColumns, AddSmallOpcodeInteractionColumns)
}

func (claim AssertEqOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AssertEqOpcodeTraceColumns, AssertEqOpcodeInteractionColumns)
}

func (claim AssertEqDoubleDerefOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AssertEqDoubleDerefOpcodeTraceColumns, AssertEqDoubleDerefOpcodeInteractionColumns)
}

func (claim AssertEqImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AssertEqImmOpcodeTraceColumns, AssertEqImmOpcodeInteractionColumns)
}

func (claim BlakeCompressOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeCompressTraceColumns, BlakeCompressInteractionColumns)
}

func (claim CallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, CallOpcodeTraceColumns, CallOpcodeInteractionColumns)
}

func (claim CallRelImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, CallRelImmOpcodeTraceColumns, CallRelImmOpcodeInteractionColumns)
}

func (claim GenericOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, GenericOpcodeTraceColumns, GenericOpcodeInteractionColumns)
}

func (claim JnzOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JnzOpcodeTraceColumns, JnzOpcodeInteractionColumns)
}

func (claim JnzTakenOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JnzTakenOpcodeTraceColumns, JnzTakenOpcodeInteractionColumns)
}

func (claim JumpOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JumpOpcodeTraceColumns, JumpOpcodeInteractionColumns)
}

func (claim JumpDoubleDerefOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JumpDoubleDerefOpcodeTraceColumns, JumpDoubleDerefOpcodeInteractionColumns)
}

func (claim JumpRelOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JumpRelOpcodeTraceColumns, JumpRelOpcodeInteractionColumns)
}

func (claim JumpRelImmOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, JumpRelImmOpcodeTraceColumns, JumpRelImmOpcodeInteractionColumns)
}

func (claim MulOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MulOpcodeTraceColumns, MulOpcodeInteractionColumns)
}

func (claim MulSmallOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MulSmallOpcodeTraceColumns, MulSmallOpcodeInteractionColumns)
}

func (claim Qm31OpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, Qm31OpcodeTraceColumns, Qm31OpcodeInteractionColumns)
}

func (claim RetOpcodeClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, RetOpcodeTraceColumns, RetOpcodeInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Builtins              ║
// ╚══════════════════════════════════╝

func (claim AddModBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, AddModBuiltinTraceColumns, AddModBuiltinInteractionColumns)
}

func (claim BitwiseBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BitwiseBuiltinTraceColumns, BitwiseBuiltinInteractionColumns)
}

func (claim MulModBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MulModBuiltinTraceColumns, MulModBuiltinInteractionColumns)
}

func (claim PedersenBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PedersenBuiltinTraceColumns, PedersenBuiltinInteractionColumns)
}

func (claim PoseidonBuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PoseidonBuiltinTraceColumns, PoseidonBuiltinInteractionColumns)
}

func (claim RangeCheck96BuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, RangeCheck96BuiltinTraceColumns, RangeCheck96BuiltinInteractionColumns)
}

func (claim RangeCheck128BuiltinClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, RangeCheck128BuiltinTraceColumns, RangeCheck128BuiltinInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║               Blake              ║
// ╚══════════════════════════════════╝

func (claim BlakeRoundClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeRoundTraceColumns, BlakeRoundInteractionColumns)
}

func (claim BlakeGClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeGTraceColumns, BlakeGInteractionColumns)
}

func (claim BlakeRoundSigmaClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	for i := 0; i < 16; i++ {
		k := NewPreprocessedColumnBlakeSigma(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)
}

func (claim TripleXor32Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, TripleXor32TraceColumns, TripleXor32InteractionColumns)
}

func (claim VerifyBitwiseXor12Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, VerifyBitwiseXor12TraceColumns, VerifyBitwiseXor12InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Pedersen              ║
// ╚══════════════════════════════════╝

func (claim PartialEcMulClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PartialEcMulTraceColumns, PartialEcMulInteractionColumns)
}

func (claim PedersenPointsTableClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	for i := 0; i < pedersenPointsTableColumns; i++ {
		k := NewPreprocessedColumnPedersenPoints(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Poseidon              ║
// ╚══════════════════════════════════╝

func (claim Poseidon3PartialRoundsChainClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, Poseidon3PartialRoundsTraceColumns, Poseidon3PartialRoundsInteractionColumns)
}

func (claim PoseidonFullRoundChainClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PoseidonFullRoundTraceColumns, PoseidonFullRoundInteractionColumns)
}

func (claim Cube252Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, Cube252TraceColumns, Cube252InteractionColumns)
}

func (claim PoseidonRoundKeysClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	for i := 0; i < poseidonRoundKeysColumns; i++ {
		k := NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(uint8(i))).Key(api)
		(*usedPreprocessed)[k] = frontend.Variable(1)
	}

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)
}

func (claim RangeCheckFelt252Width27Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, RangeCheckFelt252Width27TraceColumns, RangeCheckFelt252Width27InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Memory/Lookup          ║
// ╚══════════════════════════════════╝

func (claim MemoryAddressToIDClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MemoryAddressToIdTraceColumns, MemoryAddressToIdInteractionColumns)
}

func (claim MemoryIdToBigBigClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MemoryIdToBigBigTraceCols, MemoryIdToBigBigInteractionColumns)
}

func (claim MemoryIdToBigSmallClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, MemoryIdToBigSmallTraceCols, MemoryIdToBigSmallInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyInstruction        ║
// ╚══════════════════════════════════╝

func (claim VerifyInstructionClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, VerifyInstructionTraceColumns, VerifyInstructionInteractionColumns)
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

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor7Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor8Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor9Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Range Check           ║
// ╚══════════════════════════════════╝

func (claim RangeCheck33333Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
	}
	k := NewPreprocessedColumnRangeCheck5(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, frontend.Variable(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, frontend.Variable(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck5(values, frontend.Variable(4)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck3663Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(3),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(3),
	}
	k := NewPreprocessedColumnRangeCheck4(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck43Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(3),
	}
	k := NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck44Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(4),
	}
	k := NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck4444Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
	}
	k := NewPreprocessedColumnRangeCheck4(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck4(values, frontend.Variable(3)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck54Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(5),
		frontend.Variable(4),
	}
	k := NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck6Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck725Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(7),
		frontend.Variable(2),
		frontend.Variable(5),
	}
	k := NewPreprocessedColumnRangeCheck3(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck3(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck3(values, frontend.Variable(2)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck8Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(frontend.Variable(8)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck99Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	values := []frontend.Variable{
		frontend.Variable(9),
		frontend.Variable(9),
	}
	k := NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)
	k = NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck11Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck12Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck18Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck19Claim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) TreeMaskPoints {
	k := NewPreprocessedColumnSeq(claim.LogSize).Key(api)
	(*usedPreprocessed)[k] = frontend.Variable(1)

	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, LookupTraceColumns, LookupInteractionColumns)
}
