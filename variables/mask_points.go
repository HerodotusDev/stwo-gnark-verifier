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
func (claim CairoClaim) MaskPoints(api frontend.API, oodsPoint circle.Point, circleChip *circle.CircleChip, circuitData CircuitData) cairo_components.TreeMaskPoints {
	var parts []cairo_components.TreeMaskPoints
	usedPreprocessed := make(map[uints.U64]frontend.Variable, len(cairo_components.PreprocessedColumns))

	// Opcodes
	if circuitData.ComponentConfig[0] {
		parts = append(parts, claim.Add.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[1] {
		parts = append(parts, claim.AddSmall.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[2] {
		parts = append(parts, claim.AddAp.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[3] {
		parts = append(parts, claim.AssertEq.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[4] {
		parts = append(parts, claim.AssertEqImm.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[5] {
		parts = append(parts, claim.AssertEqDoubleDeref.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[6] {
		parts = append(parts, claim.Blake.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[7] {
		parts = append(parts, claim.Call.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[8] {
		parts = append(parts, claim.CallRelImm.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[9] {
		parts = append(parts, claim.Generic.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[10] {
		parts = append(parts, claim.Jnz.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[11] {
		parts = append(parts, claim.JnzTaken.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[12] {
		parts = append(parts, claim.Jump.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[13] {
		parts = append(parts, claim.JumpDoubleDeref.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[14] {
		parts = append(parts, claim.JumpRel.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[15] {
		parts = append(parts, claim.JumpRelImm.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[16] {
		parts = append(parts, claim.Mul.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[17] {
		parts = append(parts, claim.MulSmall.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[18] {
		parts = append(parts, claim.Qm31.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[19] {
		parts = append(parts, claim.Ret.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		parts = append(parts, claim.VerifyInstruction.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		parts = append(parts, claim.BlakeRound.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[22] {
		parts = append(parts, claim.BlakeG.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[23] {
		parts = append(parts, claim.BlakeRoundSigma.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[24] {
		parts = append(parts, claim.TripleXor32.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[25] {
		parts = append(parts, claim.VerifyBitwiseXor12.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		parts = append(parts, claim.AddModBuiltin.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[27] {
		parts = append(parts, claim.BitwiseBuiltin.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[28] {
		parts = append(parts, claim.MulModBuiltin.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[29] {
		parts = append(parts, claim.PedersenBuiltin.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[30] {
		parts = append(parts, claim.PoseidonBuiltin.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[31] {
		parts = append(parts, claim.RangeCheck96.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[32] {
		parts = append(parts, claim.RangeCheck128.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		parts = append(parts, claim.PartialEcMul.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[34] {
		parts = append(parts, claim.PedersenPointsTable.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		parts = append(parts, claim.Poseidon3PartialRoundsChain.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[36] {
		parts = append(parts, claim.PoseidonFullRoundChain.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[37] {
		parts = append(parts, claim.Cube252.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[38] {
		parts = append(parts, claim.PoseidonRoundKeys.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[39] {
		parts = append(parts, claim.RangeCheckFelt252Width27.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		parts = append(parts, claim.MemoryAddressToID.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[41] {
		parts = append(parts, claim.MemoryIDToBigBig.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[42] {
		parts = append(parts, claim.MemoryIDToBigSmall.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Range checks
	if circuitData.ComponentConfig[43] {
		parts = append(parts, claim.RC6.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[44] {
		parts = append(parts, claim.RC8.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[45] {
		parts = append(parts, claim.RC11.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[46] {
		parts = append(parts, claim.RC12.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[47] {
		parts = append(parts, claim.RC18.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[48] {
		parts = append(parts, claim.RC19.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[49] {
		parts = append(parts, claim.RC43.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[50] {
		parts = append(parts, claim.RC44.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[51] {
		parts = append(parts, claim.RC54.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[52] {
		parts = append(parts, claim.RC99.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[53] {
		parts = append(parts, claim.RC725.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[54] {
		parts = append(parts, claim.RC3663.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[55] {
		parts = append(parts, claim.RC4444.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[56] {
		parts = append(parts, claim.RC33333.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		parts = append(parts, claim.VerifyBitwiseXor4.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[58] {
		parts = append(parts, claim.VerifyBitwiseXor7.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[59] {
		parts = append(parts, claim.VerifyBitwiseXor8.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}
	if circuitData.ComponentConfig[60] {
		parts = append(parts, claim.VerifyBitwiseXor9.MaskPoints(api, oodsPoint, circleChip, &usedPreprocessed))
	}

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
