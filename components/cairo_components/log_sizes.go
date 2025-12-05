package cairo_components

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// TreeLogSizes contains the column log sizes for each tree.
type TreeLogSizes [][]frontend.Variable

func init() {
	solver.RegisterHint(MaxLogSizeHint)
}

func FlattenTree[T any](tree [][]T) []T {
	result := make([]T, 0)
	for _, group := range tree {
		result = append(result, group...)
	}
	return result
}

func MaxLogSize(api frontend.API, logSizes TreeLogSizes) frontend.Variable {
	// flatten the log sizes
	flattened := FlattenTree(logSizes)
	// get the hinted max log size
	result, err := api.Compiler().NewHint(MaxLogSizeHint, 1, flattened...)
	if err != nil {
		panic(err)
	}
	assertIsMax(api, flattened, result[0])
	return result[0]
}

func assertIsMax(api frontend.API, l []frontend.Variable, m frontend.Variable) {
	cmp := cmp.NewBoundedComparator(api, big.NewInt(1<<8), false)
	for _, size := range l {
		cmp.AssertIsLessEq(size, m)
	}
}

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
	logSizes := make(TreeLogSizes, N_TREES)
	for i := range logSizes {
		logSizes[i] = make([]frontend.Variable, 0)
	}
	if traceCols > 0 {
		logSizes[MAIN_IDX] = appendRepeat(logSizes[MAIN_IDX], logSize, traceCols)
	}
	if interactionCols > 0 {
		logSizes[INTERACTION_IDX] = appendRepeat(logSizes[INTERACTION_IDX], logSize, interactionCols)
	}
	return logSizes
}

// ConcatTreeLogSizes concatenates the columns of multiple TreeLogSizes.
func ConcatTreeLogSizes(trees ...TreeLogSizes) TreeLogSizes {
	result := make(TreeLogSizes, N_TREES)
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

// ╔══════════════════════════════════╗
// ║            Opcodes               ║
// ╚══════════════════════════════════╝

func (claim AddOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, addOpcodeTraceColumns, addOpcodeInteractionColumns)
}

func (claim AddApOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, addApOpcodeTraceColumns, addApOpcodeInteractionColumns)
}

func (claim AddSmallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, addSmallOpcodeTraceColumns, addSmallOpcodeInteractionColumns)
}

func (claim AssertEqOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, assertEqOpcodeTraceColumns, assertEqOpcodeInteractionColumns)
}

func (claim AssertEqDoubleDerefOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, assertEqDoubleDerefOpcodeTraceColumns, assertEqDoubleDerefOpcodeInteractionColumns)
}

func (claim AssertEqImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, assertEqImmOpcodeTraceColumns, assertEqImmOpcodeInteractionColumns)
}

func (claim BlakeCompressOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, blakeCompressTraceColumns, blakeCompressInteractionColumns)
}

func (claim CallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, callOpcodeTraceColumns, callOpcodeInteractionColumns)
}

func (claim CallRelImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, callRelImmOpcodeTraceColumns, callRelImmOpcodeInteractionColumns)
}

func (claim GenericOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, genericOpcodeTraceColumns, genericOpcodeInteractionColumns)
}

func (claim JnzOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jnzOpcodeTraceColumns, jnzOpcodeInteractionColumns)
}

func (claim JnzTakenOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jnzTakenOpcodeTraceColumns, jnzTakenOpcodeInteractionColumns)
}

func (claim JumpOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jumpOpcodeTraceColumns, jumpOpcodeInteractionColumns)
}

func (claim JumpDoubleDerefOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jumpDoubleDerefOpcodeTraceColumns, jumpDoubleDerefOpcodeInteractionColumns)
}

func (claim JumpRelOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jumpRelOpcodeTraceColumns, jumpRelOpcodeInteractionColumns)
}

func (claim JumpRelImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, jumpRelImmOpcodeTraceColumns, jumpRelImmOpcodeInteractionColumns)
}

func (claim MulOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, mulOpcodeTraceColumns, mulOpcodeInteractionColumns)
}

func (claim MulSmallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, mulSmallOpcodeTraceColumns, mulSmallOpcodeInteractionColumns)
}

func (claim Qm31OpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, qm31OpcodeTraceColumns, qm31OpcodeInteractionColumns)
}

func (claim RetOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, retOpcodeTraceColumns, retOpcodeInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Builtins              ║
// ╚══════════════════════════════════╝

func (claim AddModBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, addModBuiltinTraceColumns, addModBuiltinInteractionColumns)
}

func (claim BitwiseBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, bitwiseBuiltinTraceColumns, bitwiseBuiltinInteractionColumns)
}

func (claim MulModBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, mulModBuiltinTraceColumns, mulModBuiltinInteractionColumns)
}

func (claim PedersenBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, pedersenBuiltinTraceColumns, pedersenBuiltinInteractionColumns)
}

func (claim PoseidonBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, poseidonBuiltinTraceColumns, poseidonBuiltinInteractionColumns)
}

func (claim RangeCheck96BuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, rangeCheck96BuiltinTraceColumns, rangeCheck96BuiltinInteractionColumns)
}

func (claim RangeCheck128BuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, rangeCheck128BuiltinTraceColumns, rangeCheck128BuiltinInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║               Blake              ║
// ╚══════════════════════════════════╝

func (claim BlakeRoundClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, blakeRoundTraceColumns, blakeRoundInteractionColumns)
}

func (claim BlakeGClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, blakeGTraceColumns, blakeGInteractionColumns)
}

func (BlakeRoundSigmaClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(BlakeRoundSigmaLogSize, BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)
}

func (claim TripleXor32Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, tripleXor32TraceColumns, tripleXor32InteractionColumns)
}

func (claim VerifyBitwiseXor12Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, VerifyBitwiseXor12TraceColumns, VerifyBitwiseXor12InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Pedersen              ║
// ╚══════════════════════════════════╝

func (claim PartialEcMulClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, partialEcMulTraceColumns, partialEcMulInteractionColumns)
}

func (PedersenPointsTableClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(PedersenPointsTableLogSize, PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Poseidon              ║
// ╚══════════════════════════════════╝

func (claim Poseidon3PartialRoundsChainClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, poseidon3PartialRoundsTraceColumns, poseidon3PartialRoundsInteractionColumns)
}

func (claim PoseidonFullRoundChainClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, poseidonFullRoundTraceColumns, poseidonFullRoundInteractionColumns)
}

func (claim Cube252Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, cube252TraceColumns, cube252InteractionColumns)
}

func (PoseidonRoundKeysClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(PoseidonRoundKeysLogSize, PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)
}

func (claim RangeCheckFelt252Width27Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, rangeCheckFelt252Width27TraceColumns, rangeCheckFelt252Width27InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Memory/Lookup          ║
// ╚══════════════════════════════════╝

func (claim MemoryAddressToIDClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, memoryAddressToIdTraceColumns, memoryAddressToIdInteractionColumns)
}

func (claim MemoryIdToBigBigClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, memoryIdToBigBigTraceCols, memoryIdToBigBigInteractionColumns)
}

func (claim MemoryIdToBigSmallClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, memoryIdToBigSmallTraceCols, memoryIdToBigSmallInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Range Checks           ║
// ╚══════════════════════════════════╝

func (claim RangeCheck6Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck8Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck11Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck12Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck18Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck19Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck43Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck44Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck54Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck99Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck725Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck3663Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck33333Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim RangeCheck4444Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         Verify Bitwise XOR       ║
// ╚══════════════════════════════════╝

func (claim VerifyBitwiseXor4Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor7Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor8Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

func (claim VerifyBitwiseXor9Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, LookupTraceColumns, LookupInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyInstruction        ║
// ╚══════════════════════════════════╝

func (claim VerifyInstructionClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, verifyInstructionTraceColumns, verifyInstructionInteractionColumns)
}
