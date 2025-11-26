package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
)

func appendMaskPointsClaimList[T interface {
	MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) cairo_components.TreeMaskPoints
}](dst *[]cairo_components.TreeMaskPoints, claims []T, oodsPoint circle.Point, circleChip *circle.CircleChip) {
	if len(claims) == 0 {
		return
	}
	for _, claim := range claims {
		*dst = append(*dst, claim.MaskPoints(oodsPoint, circleChip))
	}
}

func appendOptionalMaskPoints[T interface {
	MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) cairo_components.TreeMaskPoints
}](dst *[]cairo_components.TreeMaskPoints, claim *T, oodsPoint circle.Point, circleChip *circle.CircleChip) {
	if claim == nil {
		return
	}
	value := (*claim).MaskPoints(oodsPoint, circleChip)
	*dst = append(*dst, value)
}

func appendSimpleMaskPoints(dst *[]cairo_components.TreeMaskPoints, logSize uint32, traceCols, interactionCols int, oodsPoint circle.Point, circleChip *circle.CircleChip) {
	traceGenPoint := circleChip.Point(circleChip.NewCanonicCoset(logSize).Coset().Step())
	traceGenPointNegOne := circleChip.BaseNeg(traceGenPoint)
	oodsPointNegOne := circleChip.AddBasePoint(oodsPoint, traceGenPointNegOne)
	*dst = append(*dst, cairo_components.NewTreeMaskPoints(oodsPoint, oodsPointNegOne, traceCols, interactionCols))
}

// MaskPoints returns the per-tree sample points for the Cairo claim.
func (claim CairoClaim) MaskPoints(oodsPoint circle.Point, circleChip *circle.CircleChip) cairo_components.TreeMaskPoints {
	var parts []cairo_components.TreeMaskPoints

	// Opcodes
	appendMaskPointsClaimList(&parts, claim.Opcodes.Add, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.AddSmall, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.AddAp, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.AssertEq, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.AssertEqImm, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.AssertEqDoubleDeref, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Blake, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Call, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.CallRelImm, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Generic, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Jnz, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.JnzTaken, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Jump, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.JumpDoubleDeref, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.JumpRel, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.JumpRelImm, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Mul, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.MulSmall, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Qm31, oodsPoint, circleChip)
	appendMaskPointsClaimList(&parts, claim.Opcodes.Ret, oodsPoint, circleChip)

	// Verify instruction
	appendOptionalMaskPoints(&parts, claim.VerifyInstruction, oodsPoint, circleChip)

	// Blake context
	if ctx := claim.BlakeContext.Claim; ctx != nil {
		appendOptionalMaskPoints(&parts, ctx.BlakeRound, oodsPoint, circleChip)
		appendOptionalMaskPoints(&parts, ctx.BlakeG, oodsPoint, circleChip)
		appendSimpleMaskPoints(&parts, 4, cairo_components.BlakeRoundSigmaTraceColumns, cairo_components.BlakeRoundSigmaInteractionColumns, oodsPoint, circleChip)
		appendOptionalMaskPoints(&parts, ctx.TripleXor32, oodsPoint, circleChip)
		appendSimpleMaskPoints(&parts, 20, cairo_components.VerifyBitwiseXor12TraceColumns, cairo_components.VerifyBitwiseXor12InteractionColumns, oodsPoint, circleChip)
	}

	// Builtins
	appendOptionalMaskPoints(&parts, claim.Builtins.AddModBuiltin, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.BitwiseBuiltin, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.MulModBuiltin, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.PedersenBuiltin, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.PoseidonBuiltin, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.RangeCheck96, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.Builtins.RangeCheck128, oodsPoint, circleChip)

	// Pedersen context
	if pedersen := claim.PedersenContext.Claim; pedersen != nil {
		appendOptionalMaskPoints(&parts, pedersen.PartialEcMul, oodsPoint, circleChip)
		appendSimpleMaskPoints(&parts, 23, cairo_components.PedersenPointsTableTraceColumns, cairo_components.PedersenPointsTableInteractionColumns, oodsPoint, circleChip)
	}

	// Poseidon context
	if poseidon := claim.PoseidonContext.Claim; poseidon != nil {
		appendOptionalMaskPoints(&parts, poseidon.Poseidon3PartialRoundsChain, oodsPoint, circleChip)
		appendOptionalMaskPoints(&parts, poseidon.PoseidonFullRoundChain, oodsPoint, circleChip)
		appendOptionalMaskPoints(&parts, poseidon.Cube252, oodsPoint, circleChip)
		appendSimpleMaskPoints(&parts, 6, cairo_components.PoseidonRoundKeysTraceColumns, cairo_components.PoseidonRoundKeysInteractionColumns, oodsPoint, circleChip)
		appendOptionalMaskPoints(&parts, poseidon.RangeCheckFelt252Width27, oodsPoint, circleChip)
	}

	// Memory relations
	parts = append(parts, claim.MemoryAddressToId.MaskPoints(oodsPoint, circleChip))
	appendMaskPointsClaimList(&parts, claim.MemoryIDToValue.Big, oodsPoint, circleChip)
	appendOptionalMaskPoints(&parts, claim.MemoryIDToValue.Small, oodsPoint, circleChip)

	// Range checks simple claims.
	appendSimpleMaskPoints(&parts, 6, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 8, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 11, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 12, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 18, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 19, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 7, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 8, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 9, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 18, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 14, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 18, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 16, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 15, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)

	// Verify bitwise XOR components (simple claims).
	appendSimpleMaskPoints(&parts, 8, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 14, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 16, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)
	appendSimpleMaskPoints(&parts, 18, rangeCheckTraceColumns, rangeCheckInteractionColumns, oodsPoint, circleChip)

	return cairo_components.ConcatTreeMaskPoints(parts...)
}
