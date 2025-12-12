package components

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// TreeLogSizes contains the column log sizes for each tree.
type TreeLogSizes [][]frontend.Variable

func init() {
	solver.RegisterHint(MaxLogSizeHint)
}

// MaxLogSize returns the hinted max log size across all trees.
func MaxLogSize(api frontend.API, logSizes TreeLogSizes) frontend.Variable {
	flattened := utils.FlattenTree(logSizes)
	result, err := api.Compiler().NewHint(MaxLogSizeHint, 1, flattened...)
	if err != nil {
		panic(err)
	}
	assertIsMax(api, flattened, result[0])
	return result[0]
}

func assertIsMax(api frontend.API, logSizes []frontend.Variable, max frontend.Variable) {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(1<<8), false)
	for _, size := range logSizes {
		comparator.AssertIsLessEq(size, max)
	}
}

// MaxLogSizeHint computes the max of inputs and is registered as a hint.
func MaxLogSizeHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) == 0 {
		return nil
	}
	max := new(big.Int).Set(inputs[0])
	for i := 1; i < len(inputs); i++ {
		if inputs[i].Cmp(max) > 0 {
			max.Set(inputs[i])
		}
	}
	results[0] = new(big.Int).Set(max)
	return nil
}

// NewTreeLogSizesFromCounts builds a TreeLogSizes entry from the provided counts.
func NewTreeLogSizesFromCounts(logSize frontend.Variable, traceCols, interactionCols int) TreeLogSizes {
	logSizes := make(TreeLogSizes, cairo_components.N_TREES)
	for i := range logSizes {
		logSizes[i] = make([]frontend.Variable, 0)
	}
	if traceCols > 0 {
		logSizes[cairo_components.MAIN_IDX] = appendRepeat(logSizes[cairo_components.MAIN_IDX], logSize, traceCols)
	}
	if interactionCols > 0 {
		logSizes[cairo_components.INTERACTION_IDX] = appendRepeat(logSizes[cairo_components.INTERACTION_IDX], logSize, interactionCols)
	}
	return logSizes
}

// ConcatTreeLogSizes concatenates the columns of multiple TreeLogSizes.
func ConcatTreeLogSizes(trees ...TreeLogSizes) TreeLogSizes {
	result := make(TreeLogSizes, cairo_components.N_TREES)
	for i := range result {
		result[i] = make([]frontend.Variable, 0)
	}
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		for idx := 0; idx < len(tree); idx++ {
			result[idx] = append(result[idx], tree[idx]...)
		}
	}
	return result
}

func appendRepeat(base []frontend.Variable, value frontend.Variable, count int) []frontend.Variable {
	if count <= 0 {
		return base
	}
	for i := 0; i < count; i++ {
		base = append(base, value)
	}
	return base
}

// LogSizes returns the per-tree column log sizes for the Cairo claim.
// This is highly order dependent, so the components need to be correctly ordered
func LogSizes(claim variables.CairoClaim, circuitData variables.CircuitData) TreeLogSizes {
	var parts []TreeLogSizes

	// Opcodes
	if circuitData.ComponentConfig[0] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Add.LogSize, cairo_components.AddOpcodeTraceColumns, cairo_components.AddOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[1] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AddSmall.LogSize, cairo_components.AddSmallOpcodeTraceColumns, cairo_components.AddSmallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[2] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AddAp.LogSize, cairo_components.AddApOpcodeTraceColumns, cairo_components.AddApOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[3] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AssertEq.LogSize, cairo_components.AssertEqOpcodeTraceColumns, cairo_components.AssertEqOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[4] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AssertEqImm.LogSize, cairo_components.AssertEqImmOpcodeTraceColumns, cairo_components.AssertEqImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[5] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AssertEqDoubleDeref.LogSize, cairo_components.AssertEqDoubleDerefOpcodeTraceColumns, cairo_components.AssertEqDoubleDerefOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[6] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Blake.LogSize, cairo_components.BlakeCompressTraceColumns, cairo_components.BlakeCompressInteractionColumns))
	}
	if circuitData.ComponentConfig[7] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Call.LogSize, cairo_components.CallOpcodeTraceColumns, cairo_components.CallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[8] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.CallRelImm.LogSize, cairo_components.CallRelImmOpcodeTraceColumns, cairo_components.CallRelImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[9] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Generic.LogSize, cairo_components.GenericOpcodeTraceColumns, cairo_components.GenericOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[10] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Jnz.LogSize, cairo_components.JnzOpcodeTraceColumns, cairo_components.JnzOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[11] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.JnzTaken.LogSize, cairo_components.JnzTakenOpcodeTraceColumns, cairo_components.JnzTakenOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[12] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Jump.LogSize, cairo_components.JumpOpcodeTraceColumns, cairo_components.JumpOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[13] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.JumpDoubleDeref.LogSize, cairo_components.JumpDoubleDerefOpcodeTraceColumns, cairo_components.JumpDoubleDerefOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[14] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.JumpRel.LogSize, cairo_components.JumpRelOpcodeTraceColumns, cairo_components.JumpRelOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[15] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.JumpRelImm.LogSize, cairo_components.JumpRelImmOpcodeTraceColumns, cairo_components.JumpRelImmOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[16] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Mul.LogSize, cairo_components.MulOpcodeTraceColumns, cairo_components.MulOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[17] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.MulSmall.LogSize, cairo_components.MulSmallOpcodeTraceColumns, cairo_components.MulSmallOpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[18] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Qm31.LogSize, cairo_components.Qm31OpcodeTraceColumns, cairo_components.Qm31OpcodeInteractionColumns))
	}
	if circuitData.ComponentConfig[19] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Ret.LogSize, cairo_components.RetOpcodeTraceColumns, cairo_components.RetOpcodeInteractionColumns))
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyInstruction.LogSize, cairo_components.VerifyInstructionTraceColumns, cairo_components.VerifyInstructionInteractionColumns))
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.BlakeRound.LogSize, cairo_components.BlakeRoundTraceColumns, cairo_components.BlakeRoundInteractionColumns))
	}
	if circuitData.ComponentConfig[22] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.BlakeG.LogSize, cairo_components.BlakeGTraceColumns, cairo_components.BlakeGInteractionColumns))
	}
	if circuitData.ComponentConfig[23] {
		parts = append(parts, NewTreeLogSizesFromCounts(cairo_components.BlakeRoundSigmaLogSize, cairo_components.BlakeRoundSigmaTraceColumns, cairo_components.BlakeRoundSigmaInteractionColumns))
	}
	if circuitData.ComponentConfig[24] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.TripleXor32.LogSize, cairo_components.TripleXor32TraceColumns, cairo_components.TripleXor32InteractionColumns))
	}
	if circuitData.ComponentConfig[25] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyBitwiseXor12.LogSize, cairo_components.VerifyBitwiseXor12TraceColumns, cairo_components.VerifyBitwiseXor12InteractionColumns))
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.AddModBuiltin.LogSize, cairo_components.AddModBuiltinTraceColumns, cairo_components.AddModBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[27] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.BitwiseBuiltin.LogSize, cairo_components.BitwiseBuiltinTraceColumns, cairo_components.BitwiseBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[28] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.MulModBuiltin.LogSize, cairo_components.MulModBuiltinTraceColumns, cairo_components.MulModBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[29] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.PedersenBuiltin.LogSize, cairo_components.PedersenBuiltinTraceColumns, cairo_components.PedersenBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[30] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.PoseidonBuiltin.LogSize, cairo_components.PoseidonBuiltinTraceColumns, cairo_components.PoseidonBuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[31] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RangeCheck96.LogSize, cairo_components.RangeCheck96BuiltinTraceColumns, cairo_components.RangeCheck96BuiltinInteractionColumns))
	}
	if circuitData.ComponentConfig[32] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RangeCheck128.LogSize, cairo_components.RangeCheck128BuiltinTraceColumns, cairo_components.RangeCheck128BuiltinInteractionColumns))
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.PartialEcMul.LogSize, cairo_components.PartialEcMulTraceColumns, cairo_components.PartialEcMulInteractionColumns))
	}
	if circuitData.ComponentConfig[34] {
		parts = append(parts, NewTreeLogSizesFromCounts(cairo_components.PedersenPointsTableLogSize, cairo_components.PedersenPointsTableTraceColumns, cairo_components.PedersenPointsTableInteractionColumns))
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Poseidon3PartialRoundsChain.LogSize, cairo_components.Poseidon3PartialRoundsTraceColumns, cairo_components.Poseidon3PartialRoundsInteractionColumns))
	}
	if circuitData.ComponentConfig[36] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.PoseidonFullRoundChain.LogSize, cairo_components.PoseidonFullRoundTraceColumns, cairo_components.PoseidonFullRoundInteractionColumns))
	}
	if circuitData.ComponentConfig[37] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.Cube252.LogSize, cairo_components.Cube252TraceColumns, cairo_components.Cube252InteractionColumns))
	}
	if circuitData.ComponentConfig[38] {
		parts = append(parts, NewTreeLogSizesFromCounts(cairo_components.PoseidonRoundKeysLogSize, cairo_components.PoseidonRoundKeysTraceColumns, cairo_components.PoseidonRoundKeysInteractionColumns))
	}
	if circuitData.ComponentConfig[39] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RangeCheckFelt252Width27.LogSize, cairo_components.RangeCheckFelt252Width27TraceColumns, cairo_components.RangeCheckFelt252Width27InteractionColumns))
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.MemoryAddressToID.LogSize, cairo_components.MemoryAddressToIDTraceColumns, cairo_components.MemoryAddressToIDInteractionColumns))
	}
	if circuitData.ComponentConfig[41] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.MemoryIDToBigBig.LogSize, cairo_components.MemoryIDToBigBigTraceCols, cairo_components.MemoryIDToBigBigInteractionColumns))
	}
	if circuitData.ComponentConfig[42] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.MemoryIDToBigSmall.LogSize, cairo_components.MemoryIDToBigSmallTraceCols, cairo_components.MemoryIDToBigSmallInteractionColumns))
	}

	// Range checks
	if circuitData.ComponentConfig[43] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC6.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[44] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC8.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[45] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC11.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[46] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC12.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[47] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC18.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[48] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC19.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[49] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC43.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[50] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC44.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[51] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC54.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[52] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC99.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[53] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC725.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[54] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC3663.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[55] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC4444.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[56] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.RC33333.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyBitwiseXor4.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[58] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyBitwiseXor7.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[59] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyBitwiseXor8.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}
	if circuitData.ComponentConfig[60] {
		parts = append(parts, NewTreeLogSizesFromCounts(claim.VerifyBitwiseXor9.LogSize, cairo_components.LookupTraceColumns, cairo_components.LookupInteractionColumns))
	}

	return ConcatTreeLogSizes(parts...)
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
