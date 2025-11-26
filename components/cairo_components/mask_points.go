package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
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
		maskPoints[INTERACTION_IDX] = appendRepeatMaskPoints(maskPoints[INTERACTION_IDX], []circle.Point{point, pointNegOne}, 4)
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
	traceGenPoint := circleChip.Point(circleChip.NewCanonicCoset(logSize).Coset().Step())
	traceGenPointNegOne := circleChip.BaseNeg(traceGenPoint)
	return circleChip.AddBasePoint(oodsPoint, traceGenPointNegOne)
}

// ╔══════════════════════════════════╗
// ║            Opcodes               ║
// ╚══════════════════════════════════╝

func (claim AddOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addOpcodeTraceColumns, addOpcodeInteractionColumns)
}

func (claim AddApOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addApOpcodeTraceColumns, addApOpcodeInteractionColumns)
}

func (claim AddSmallOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addSmallOpcodeTraceColumns, addSmallOpcodeInteractionColumns)
}

func (claim AssertEqOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqOpcodeTraceColumns, assertEqOpcodeInteractionColumns)
}

func (claim AssertEqDoubleDerefOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqDoubleDerefOpcodeTraceColumns, assertEqDoubleDerefOpcodeInteractionColumns)
}

func (claim AssertEqImmOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, assertEqImmOpcodeTraceColumns, assertEqImmOpcodeInteractionColumns)
}

func (claim BlakeCompressOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeCompressTraceColumns, blakeCompressInteractionColumns)
}

func (claim CallOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, callOpcodeTraceColumns, callOpcodeInteractionColumns)
}

func (claim CallRelImmOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, callRelImmOpcodeTraceColumns, callRelImmOpcodeInteractionColumns)
}

func (claim GenericOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, genericOpcodeTraceColumns, genericOpcodeInteractionColumns)
}

func (claim JnzOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jnzOpcodeTraceColumns, jnzOpcodeInteractionColumns)
}

func (claim JnzTakenOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jnzTakenOpcodeTraceColumns, jnzTakenOpcodeInteractionColumns)
}

func (claim JumpOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpOpcodeTraceColumns, jumpOpcodeInteractionColumns)
}

func (claim JumpDoubleDerefOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpDoubleDerefOpcodeTraceColumns, jumpDoubleDerefOpcodeInteractionColumns)
}

func (claim JumpRelOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpRelOpcodeTraceColumns, jumpRelOpcodeInteractionColumns)
}

func (claim JumpRelImmOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, jumpRelImmOpcodeTraceColumns, jumpRelImmOpcodeInteractionColumns)
}

func (claim MulOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulOpcodeTraceColumns, mulOpcodeInteractionColumns)
}

func (claim MulSmallOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulSmallOpcodeTraceColumns, mulSmallOpcodeInteractionColumns)
}

func (claim Qm31OpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, qm31OpcodeTraceColumns, qm31OpcodeInteractionColumns)
}

func (claim RetOpcodeClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, retOpcodeTraceColumns, retOpcodeInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Builtins              ║
// ╚══════════════════════════════════╝

func (claim AddModBuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, addModBuiltinTraceColumns, addModBuiltinInteractionColumns)
}

func (claim BitwiseBuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, bitwiseBuiltinTraceColumns, bitwiseBuiltinInteractionColumns)
}

func (claim MulModBuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, mulModBuiltinTraceColumns, mulModBuiltinInteractionColumns)
}

func (claim PedersenBuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, pedersenBuiltinTraceColumns, pedersenBuiltinInteractionColumns)
}

func (claim PoseidonBuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidonBuiltinTraceColumns, poseidonBuiltinInteractionColumns)
}

func (claim RangeCheck96BuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheck96BuiltinTraceColumns, rangeCheck96BuiltinInteractionColumns)
}

func (claim RangeCheck128BuiltinClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheck128BuiltinTraceColumns, rangeCheck128BuiltinInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║               Blake              ║
// ╚══════════════════════════════════╝

func (claim BlakeRoundClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeRoundTraceColumns, blakeRoundInteractionColumns)
}

func (claim BlakeGClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, blakeGTraceColumns, blakeGInteractionColumns)
}

func (BlakeRoundSigmaClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, blakeRoundSigmaLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)
}

func (claim TripleXor32Claim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, claim.LogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, tripleXor32TraceColumns, tripleXor32InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Pedersen              ║
// ╚══════════════════════════════════╝

func (claim PartialEcMulClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, partialEcMulTraceColumns, partialEcMulInteractionColumns)
}

func (PedersenPointsTableClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, pedersenPointsTableLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Poseidon              ║
// ╚══════════════════════════════════╝

func (claim Poseidon3PartialRoundsChainClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidon3PartialRoundsTraceColumns, poseidon3PartialRoundsInteractionColumns)
}

func (claim PoseidonFullRoundChainClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, poseidonFullRoundTraceColumns, poseidonFullRoundInteractionColumns)
}

func (claim Cube252Claim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, cube252TraceColumns, cube252InteractionColumns)
}

func (PoseidonRoundKeysClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, poseidonRoundKeysLogSize)
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)
}

func (claim RangeCheckFelt252Width27Claim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, rangeCheckFelt252Width27TraceColumns, rangeCheckFelt252Width27InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Memory/Lookup          ║
// ╚══════════════════════════════════╝

func (claim MemoryAddressToIdClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryAddressToIdTraceColumns, memoryAddressToIdInteractionColumns)
}

func (claim MemoryIdToBigBigClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryIdToBigBigTraceCols, memoryIdToBigBigInteractionColumns)
}

func (claim MemoryIdToBigSmallClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, memoryIdToBigSmallTraceCols, memoryIdToBigSmallInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyInstruction        ║
// ╚══════════════════════════════════╝

func (claim VerifyInstructionClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) TreeMaskPoints {
	oodsPointNegOne := oodsPointNegOne(oodsPoint, circleChip, u8Value(claim.LogSize))
	return NewTreeMaskPoints(oodsPoint, oodsPointNegOne, verifyInstructionTraceColumns, verifyInstructionInteractionColumns)
}
