package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func appendMaskPointsClaimList[T interface {
	MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) cairo_components.TreeMaskPoints
}](api frontend.API, dst *[]cairo_components.TreeMaskPoints, claims []T, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) {
	if len(claims) == 0 {
		return
	}
	for _, claim := range claims {
		*dst = append(*dst, claim.MaskPoints(api, oodsPoint, circleChip, usedPreprocessed))
	}
}

func appendOptionalMaskPoints[T interface {
	MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) cairo_components.TreeMaskPoints
}](api frontend.API, dst *[]cairo_components.TreeMaskPoints, claim *T, oodsPoint circle.Point, circleChip *circle.CircleChip, usedPreprocessed *map[uints.U64]frontend.Variable) {
	if claim == nil {
		return
	}
	value := (*claim).MaskPoints(api, oodsPoint, circleChip, usedPreprocessed)
	*dst = append(*dst, value)
}

// MaskPoints returns the per-tree sample points for the Cairo claim.
func (claim CairoClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip) cairo_components.TreeMaskPoints {
	var parts []cairo_components.TreeMaskPoints
	usedPreprocessed := make(map[uints.U64]frontend.Variable, len(cairo_components.PreprocessedColumns))

	// Opcodes
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Add, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.AddSmall, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.AddAp, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.AssertEq, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.AssertEqImm, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.AssertEqDoubleDeref, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Blake, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Call, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.CallRelImm, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Generic, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Jnz, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.JnzTaken, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Jump, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.JumpDoubleDeref, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.JumpRel, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.JumpRelImm, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Mul, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.MulSmall, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Qm31, oodsPoint, circleChip, &usedPreprocessed)
	appendMaskPointsClaimList(api, &parts, claim.Opcodes.Ret, oodsPoint, circleChip, &usedPreprocessed)

	// Verify instruction
	appendOptionalMaskPoints(api, &parts, claim.VerifyInstruction, oodsPoint, circleChip, &usedPreprocessed)

	// Blake context
	if ctx := claim.BlakeContext.Claim; ctx != nil {
		appendOptionalMaskPoints(api, &parts, ctx.BlakeRound, oodsPoint, circleChip, &usedPreprocessed)
		appendOptionalMaskPoints(api, &parts, ctx.BlakeG, oodsPoint, circleChip, &usedPreprocessed)
		parts = append(parts, ctx.BlakeRoundSigma.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
		appendOptionalMaskPoints(api, &parts, ctx.TripleXor32, oodsPoint, circleChip, &usedPreprocessed)
		parts = append(parts, ctx.VerifyBitwiseXor12.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Builtins
	appendOptionalMaskPoints(api, &parts, claim.Builtins.AddModBuiltin, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.BitwiseBuiltin, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.MulModBuiltin, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.PedersenBuiltin, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.PoseidonBuiltin, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.RangeCheck96, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.Builtins.RangeCheck128, oodsPoint, circleChip, &usedPreprocessed)

	// Pedersen context
	if pedersen := claim.PedersenContext.Claim; pedersen != nil {
		appendOptionalMaskPoints(api, &parts, pedersen.PartialEcMul, oodsPoint, circleChip, &usedPreprocessed)
		parts = append(parts, pedersen.PedersenPointsTable.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Poseidon context
	if poseidon := claim.PoseidonContext.Claim; poseidon != nil {
		appendOptionalMaskPoints(api, &parts, poseidon.Poseidon3PartialRoundsChain, oodsPoint, circleChip, &usedPreprocessed)
		appendOptionalMaskPoints(api, &parts, poseidon.PoseidonFullRoundChain, oodsPoint, circleChip, &usedPreprocessed)
		appendOptionalMaskPoints(api, &parts, poseidon.Cube252, oodsPoint, circleChip, &usedPreprocessed)
		parts = append(parts, poseidon.PoseidonRoundKeys.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
		appendOptionalMaskPoints(api, &parts, poseidon.RangeCheckFelt252Width27, oodsPoint, circleChip, &usedPreprocessed)
	}

	// Memory relations
	parts = append(parts, claim.MemoryAddressToId.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	appendMaskPointsClaimList(api, &parts, claim.MemoryIDToValue.Big, oodsPoint, circleChip, &usedPreprocessed)
	appendOptionalMaskPoints(api, &parts, claim.MemoryIDToValue.Small, oodsPoint, circleChip, &usedPreprocessed)

	// Range checks simple claims.
	parts = append(parts, claim.RangeChecks.RC6.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC8.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC11.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC12.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC18.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC19.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC4_3.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC4_4.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC5_4.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC9_9.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC7_2_5.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC3_6_6_3.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC4_4_4_4.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.RangeChecks.RC3_3_3_3_3.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))

	// Verify bitwise XOR components (simple claims).
	parts = append(parts, claim.VerifyBitwiseXor4.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.VerifyBitwiseXor7.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.VerifyBitwiseXor8.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	parts = append(parts, claim.VerifyBitwiseXor9.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))

	// Concatenate tree mask points
	maskPoints := cairo_components.ConcatTreeMaskPoints(parts...)

	// Add preprocessed mask points
	preprocessedMaskPoints := make([][]circle.Point, len(cairo_components.PreprocessedColumns))
	for i, column := range cairo_components.PreprocessedColumns {
		key := column.Key(api)
		preprocessedMaskPoints[i] = []circle.Point{}
		if used, ok := usedPreprocessed[key]; ok && used == frontend.Variable(1) {
			preprocessedMaskPoints[i] = []circle.Point{oodsPoint}
		}
	}
	maskPoints[cairo_components.PREPROCESSED_IDX] = preprocessedMaskPoints

	// Add CP mask points
	maskPoints[cairo_components.CP_IDX] = [][]circle.Point{
		{oodsPoint},
		{oodsPoint},
		{oodsPoint},
		{oodsPoint},
	}

	return maskPoints
}
