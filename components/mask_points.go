package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

// TreeMaskPoints contains the sample points for each tree.
type TreeMaskPoints [][][]circle.Point

// NewTreeMaskPoints builds a TreeMaskPoints entry from the provided point.
func NewTreeMaskPoints(point, pointNegOne circle.Point, traceCols, interactionCols int) TreeMaskPoints {
	maskPoints := make(TreeMaskPoints, cairo_components.N_TREES)
	for i := range maskPoints {
		maskPoints[i] = make([][]circle.Point, 0)
	}
	if traceCols > 0 {
		maskPoints[cairo_components.MAIN_IDX] = appendRepeatMaskPoints(maskPoints[cairo_components.MAIN_IDX], []circle.Point{point}, traceCols)
	}
	if interactionCols > 0 {
		maskPoints[cairo_components.INTERACTION_IDX] = appendRepeatMaskPoints(maskPoints[cairo_components.INTERACTION_IDX], []circle.Point{point}, interactionCols-4)
		maskPoints[cairo_components.INTERACTION_IDX] = appendRepeatMaskPoints(maskPoints[cairo_components.INTERACTION_IDX], []circle.Point{pointNegOne, point}, 4)
	}
	return maskPoints
}

// ConcatTreeMaskPoints concatenates the columns of multiple TreeMaskPoints.
func ConcatTreeMaskPoints(trees ...TreeMaskPoints) TreeMaskPoints {
	result := make(TreeMaskPoints, cairo_components.N_TREES)
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

// MaskPoints returns the per-tree sample points for the Cairo claim.
func MaskPoints(_ frontend.API, claim variables.CairoClaim, oodsPoint circle.Point, circleChip *circle.CircleChip, circuitData variables.CircuitData) TreeMaskPoints {
	var parts []TreeMaskPoints

	// Opcodes
	if circuitData.ComponentConfig[0] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Add.LogSize), cairo_components.AddOpcodeTraceColumns, cairo_components.AddOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[1] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AddSmall.LogSize), cairo_components.AddSmallOpcodeTraceColumns, cairo_components.AddSmallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[2] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AddAp.LogSize), cairo_components.AddApOpcodeTraceColumns, cairo_components.AddApOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[3] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AssertEq.LogSize), cairo_components.AssertEqOpcodeTraceColumns, cairo_components.AssertEqOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[4] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AssertEqImm.LogSize), cairo_components.AssertEqImmOpcodeTraceColumns, cairo_components.AssertEqImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[5] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AssertEqDoubleDeref.LogSize), cairo_components.AssertEqDoubleDerefOpcodeTraceColumns, cairo_components.AssertEqDoubleDerefOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[6] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Blake.LogSize), cairo_components.BlakeCompressTraceColumns, cairo_components.BlakeCompressInteractionColumns))
	}
	if circuitData.ComponentConfig[7] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Call.LogSize), cairo_components.CallOpcodeTraceColumns, cairo_components.CallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[8] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.CallRelImm.LogSize), cairo_components.CallRelImmOpcodeTraceColumns, cairo_components.CallRelImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[9] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Generic.LogSize), cairo_components.GenericOpcodeTraceColumns, cairo_components.GenericOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[10] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Jnz.LogSize), cairo_components.JnzOpcodeTraceColumns, cairo_components.JnzOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[11] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.JnzTaken.LogSize), cairo_components.JnzTakenOpcodeTraceColumns, cairo_components.JnzTakenOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[12] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Jump.LogSize), cairo_components.JumpOpcodeTraceColumns, cairo_components.JumpOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[13] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.JumpDoubleDeref.LogSize), cairo_components.JumpDoubleDerefOpcodeTraceColumns, cairo_components.JumpDoubleDerefOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[14] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.JumpRel.LogSize), cairo_components.JumpRelOpcodeTraceColumns, cairo_components.JumpRelOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[15] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.JumpRelImm.LogSize), cairo_components.JumpRelImmOpcodeTraceColumns, cairo_components.JumpRelImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[16] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Mul.LogSize), cairo_components.MulOpcodeTraceColumns, cairo_components.MulOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[17] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.MulSmall.LogSize), cairo_components.MulSmallOpcodeTraceColumns, cairo_components.MulSmallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[18] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Qm31.LogSize), cairo_components.Qm31OpcodeTraceColumns, cairo_components.Qm31OpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[19] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Ret.LogSize), cairo_components.RetOpcodeTraceColumns, cairo_components.RetOpcodeInteractionColumns))
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyInstruction.LogSize), cairo_components.VerifyInstructionTraceColumns, cairo_components.VerifyInstructionInteractionColumns))
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.BlakeRound.LogSize), cairo_components.BlakeRoundTraceColumns, cairo_components.BlakeRoundInteractionColumns))
	}
	if circuitData.ComponentConfig[22] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.BlakeG.LogSize), cairo_components.BlakeGTraceColumns, cairo_components.BlakeGInteractionColumns))
	}
	if circuitData.ComponentConfig[23] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.BlakeRoundSigma.LogSize), cairo_components.BlakeRoundSigmaTraceColumns, cairo_components.BlakeRoundSigmaInteractionColumns))
	}
	if circuitData.ComponentConfig[24] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.TripleXor32.LogSize), cairo_components.TripleXor32TraceColumns, cairo_components.TripleXor32InteractionColumns))
	}
	if circuitData.ComponentConfig[25] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyBitwiseXor12.LogSize), cairo_components.VerifyBitwiseXor12TraceColumns, cairo_components.VerifyBitwiseXor12InteractionColumns))
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.AddModBuiltin.LogSize), cairo_components.AddModBuiltinTraceColumns, cairo_components.AddModBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[27] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.BitwiseBuiltin.LogSize), cairo_components.BitwiseBuiltinTraceColumns, cairo_components.BitwiseBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[28] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.MulModBuiltin.LogSize), cairo_components.MulModBuiltinTraceColumns, cairo_components.MulModBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[29] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PedersenBuiltin.LogSize), cairo_components.PedersenBuiltinTraceColumns, cairo_components.PedersenBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[30] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PoseidonBuiltin.LogSize), cairo_components.PoseidonBuiltinTraceColumns, cairo_components.PoseidonBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[31] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RangeCheck96.LogSize), cairo_components.RangeCheck96BuiltinTraceColumns, cairo_components.RangeCheck96BuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[32] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RangeCheck128.LogSize), cairo_components.RangeCheck128BuiltinTraceColumns, cairo_components.RangeCheck128BuiltinInteractionColumns))
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PartialEcMul.LogSize), cairo_components.PartialEcMulTraceColumns, cairo_components.PartialEcMulInteractionColumns))
	}
	if circuitData.ComponentConfig[34] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PedersenPointsTable.LogSize), cairo_components.PedersenPointsTableTraceColumns, cairo_components.PedersenPointsTableInteractionColumns))
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Poseidon3PartialRoundsChain.LogSize), cairo_components.Poseidon3PartialRoundsTraceColumns, cairo_components.Poseidon3PartialRoundsInteractionColumns))
	}
	if circuitData.ComponentConfig[36] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PoseidonFullRoundChain.LogSize), cairo_components.PoseidonFullRoundTraceColumns, cairo_components.PoseidonFullRoundInteractionColumns))
	}
	if circuitData.ComponentConfig[37] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.Cube252.LogSize), cairo_components.Cube252TraceColumns, cairo_components.Cube252InteractionColumns))
	}
	if circuitData.ComponentConfig[38] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.PoseidonRoundKeys.LogSize), cairo_components.PoseidonRoundKeysTraceColumns, cairo_components.PoseidonRoundKeysInteractionColumns))
	}
	if circuitData.ComponentConfig[39] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RangeCheckFelt252Width27.LogSize), cairo_components.RangeCheckFelt252Width27TraceColumns, cairo_components.RangeCheckFelt252Width27InteractionColumns))
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.MemoryAddressToID.LogSize), cairo_components.MemoryAddressToIDTraceColumns, cairo_components.MemoryAddressToIDInteractionColumns))
	}
	if circuitData.ComponentConfig[41] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.MemoryIDToBigBig.LogSize), cairo_components.MemoryIDToBigBigTraceCols, cairo_components.MemoryIDToBigBigInteractionColumns))
	}
	if circuitData.ComponentConfig[42] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.MemoryIDToBigSmall.LogSize), cairo_components.MemoryIDToBigSmallTraceCols, cairo_components.MemoryIDToBigSmallInteractionColumns))
	}

	// Range checks
	if circuitData.ComponentConfig[43] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC6.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[44] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC8.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[45] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC11.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[46] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC12.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[47] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC18.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[48] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC19.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[49] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC43.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[50] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC44.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[51] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC54.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[52] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC99.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[53] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC725.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[54] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC3663.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[55] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC4444.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[56] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.RC33333.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyBitwiseXor4.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[58] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyBitwiseXor7.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[59] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyBitwiseXor8.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[60] {
		parts = append(parts, NewTreeMaskPoints(oodsPoint, oodsPointNegOne(oodsPoint, circleChip, claim.VerifyBitwiseXor9.LogSize), cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}

	// Concatenate tree mask points
	maskPoints := ConcatTreeMaskPoints(parts...)

	// Add preprocessed mask points
	preprocessedMaskPoints := make([][]circle.Point, cairo_components.NPreprocessedColumns)
	for i := range cairo_components.NPreprocessedColumns {
		if circuitData.PreprocessedConfig[i] {
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
