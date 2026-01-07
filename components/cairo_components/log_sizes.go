package cairo_components

import "github.com/consensys/gnark/std/math/uints"

// TreeLogSizes contains the column log sizes for each tree.
type TreeLogSizes [][]uint32

func MaxLogSize(logSizes TreeLogSizes) uint32 {
	maxLogSize := uint32(0)
	for _, group := range logSizes {
		for _, size := range group {
			if size > maxLogSize {
				maxLogSize = size
			}
		}
	}
	return maxLogSize
}

// NewTreeLogSizesFromCounts builds a TreeLogSizes entry from the provided counts.
func NewTreeLogSizesFromCounts(logSize uint32, traceCols, interactionCols int) TreeLogSizes {
	logSizes := make(TreeLogSizes, N_TREES)
	for i := range logSizes {
		logSizes[i] = make([]uint32, 0)
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
		result[i] = make([]uint32, 0)
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

func appendRepeat(base []uint32, value uint32, count int) []uint32 {
	if count <= 0 {
		return base
	}
	for i := 0; i < count; i++ {
		base = append(base, value)
	}
	return base
}

// TODO: u8Value is meant to be removed once CairoClaim is updated to use uint8 instead of uints.U8
func u8Value(u uints.U8) uint32 {
	switch v := u.Val.(type) {
	case uint8:
		return uint32(v)
	case uint16:
		return uint32(v)
	case uint32:
		return v
	case uint64:
		return uint32(v)
	case int:
		return uint32(v)
	default:
		panic("unsupported log size encoding")
	}
}

// ╔══════════════════════════════════╗
// ║            Opcodes               ║
// ╚══════════════════════════════════╝

func (claim AddOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), addOpcodeTraceColumns, addOpcodeInteractionColumns)
}

func (claim AddApOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), addApOpcodeTraceColumns, addApOpcodeInteractionColumns)
}

func (claim AddSmallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), addSmallOpcodeTraceColumns, addSmallOpcodeInteractionColumns)
}

func (claim AssertEqOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), assertEqOpcodeTraceColumns, assertEqOpcodeInteractionColumns)
}

func (claim AssertEqDoubleDerefOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), assertEqDoubleDerefOpcodeTraceColumns, assertEqDoubleDerefOpcodeInteractionColumns)
}

func (claim AssertEqImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), assertEqImmOpcodeTraceColumns, assertEqImmOpcodeInteractionColumns)
}

func (claim BlakeCompressOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), blakeCompressTraceColumns, blakeCompressInteractionColumns)
}

func (claim CallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), callOpcodeTraceColumns, callOpcodeInteractionColumns)
}

func (claim CallRelImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), callRelImmOpcodeTraceColumns, callRelImmOpcodeInteractionColumns)
}

func (claim GenericOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), genericOpcodeTraceColumns, genericOpcodeInteractionColumns)
}

func (claim JnzOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jnzOpcodeTraceColumns, jnzOpcodeInteractionColumns)
}

func (claim JnzTakenOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jnzTakenOpcodeTraceColumns, jnzTakenOpcodeInteractionColumns)
}

func (claim JumpOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jumpOpcodeTraceColumns, jumpOpcodeInteractionColumns)
}

func (claim JumpDoubleDerefOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jumpDoubleDerefOpcodeTraceColumns, jumpDoubleDerefOpcodeInteractionColumns)
}

func (claim JumpRelOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jumpRelOpcodeTraceColumns, jumpRelOpcodeInteractionColumns)
}

func (claim JumpRelImmOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), jumpRelImmOpcodeTraceColumns, jumpRelImmOpcodeInteractionColumns)
}

func (claim MulOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), mulOpcodeTraceColumns, mulOpcodeInteractionColumns)
}

func (claim MulSmallOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), mulSmallOpcodeTraceColumns, mulSmallOpcodeInteractionColumns)
}

func (claim Qm31OpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), qm31OpcodeTraceColumns, qm31OpcodeInteractionColumns)
}

func (claim RetOpcodeClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), retOpcodeTraceColumns, retOpcodeInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Builtins              ║
// ╚══════════════════════════════════╝

func (claim AddModBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), addModBuiltinTraceColumns, addModBuiltinInteractionColumns)
}

func (claim BitwiseBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), bitwiseBuiltinTraceColumns, bitwiseBuiltinInteractionColumns)
}

func (claim MulModBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), mulModBuiltinTraceColumns, mulModBuiltinInteractionColumns)
}

func (claim PedersenBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), pedersenBuiltinTraceColumns, pedersenBuiltinInteractionColumns)
}

func (claim PoseidonBuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), poseidonBuiltinTraceColumns, poseidonBuiltinInteractionColumns)
}

func (claim RangeCheck96BuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), rangeCheck96BuiltinTraceColumns, rangeCheck96BuiltinInteractionColumns)
}

func (claim RangeCheck128BuiltinClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), rangeCheck128BuiltinTraceColumns, rangeCheck128BuiltinInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║               Blake              ║
// ╚══════════════════════════════════╝

func (claim BlakeRoundClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), blakeRoundTraceColumns, blakeRoundInteractionColumns)
}

func (claim BlakeGClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), blakeGTraceColumns, blakeGInteractionColumns)
}

func (BlakeRoundSigmaClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(blakeRoundSigmaLogSize, BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)
}

func (claim TripleXor32Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(claim.LogSize, tripleXor32TraceColumns, tripleXor32InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Pedersen              ║
// ╚══════════════════════════════════╝

func (claim PartialEcMulClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), partialEcMulTraceColumns, partialEcMulInteractionColumns)
}

func (PedersenPointsTableClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(pedersenPointsTableLogSize, PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║            Poseidon              ║
// ╚══════════════════════════════════╝

func (claim Poseidon3PartialRoundsChainClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), poseidon3PartialRoundsTraceColumns, poseidon3PartialRoundsInteractionColumns)
}

func (claim PoseidonFullRoundChainClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), poseidonFullRoundTraceColumns, poseidonFullRoundInteractionColumns)
}

func (claim Cube252Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), cube252TraceColumns, cube252InteractionColumns)
}

func (PoseidonRoundKeysClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(poseidonRoundKeysLogSize, PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)
}

func (claim RangeCheckFelt252Width27Claim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), rangeCheckFelt252Width27TraceColumns, rangeCheckFelt252Width27InteractionColumns)
}

// ╔══════════════════════════════════╗
// ║           Memory/Lookup          ║
// ╚══════════════════════════════════╝

func (claim MemoryAddressToIdClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), memoryAddressToIdTraceColumns, memoryAddressToIdInteractionColumns)
}

func (claim MemoryIdToBigBigClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), memoryIdToBigBigTraceCols, memoryIdToBigBigInteractionColumns)
}

func (claim MemoryIdToBigSmallClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), memoryIdToBigSmallTraceCols, memoryIdToBigSmallInteractionColumns)
}

// ╔══════════════════════════════════╗
// ║         VerifyInstruction        ║
// ╚══════════════════════════════════╝

func (claim VerifyInstructionClaim) LogSizes() TreeLogSizes {
	return NewTreeLogSizesFromCounts(u8Value(claim.LogSize), verifyInstructionTraceColumns, verifyInstructionInteractionColumns)
}
