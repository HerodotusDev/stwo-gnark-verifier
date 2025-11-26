package variables

import "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"

const (
	rangeCheckTraceColumns       = cairo_components.LookupTraceColumns
	rangeCheckInteractionColumns = cairo_components.LookupInteractionColumns
)

func appendClaimList[T interface {
	LogSizes() cairo_components.TreeLogSizes
}](dst *[]cairo_components.TreeLogSizes, claims []T) {
	if len(claims) == 0 {
		return
	}
	for _, claim := range claims {
		*dst = append(*dst, claim.LogSizes())
	}
}

func appendOptionalClaim[T interface {
	LogSizes() cairo_components.TreeLogSizes
}](dst *[]cairo_components.TreeLogSizes, claim *T) {
	if claim == nil {
		return
	}
	value := (*claim).LogSizes()
	*dst = append(*dst, value)
}

func appendSimpleClaim(dst *[]cairo_components.TreeLogSizes, claim *SimpleLogSizeClaim, traceCols, interactionCols int) {
	if claim == nil {
		return
	}
	*dst = append(*dst, cairo_components.NewTreeLogSizesFromCounts(claim.LogSize, traceCols, interactionCols))
}

// LogSizes returns the per-tree column log sizes for the Cairo claim.
func (claim CairoClaim) LogSizes() cairo_components.TreeLogSizes {
	var parts []cairo_components.TreeLogSizes

	// Opcodes
	appendClaimList(&parts, claim.Opcodes.Add)
	appendClaimList(&parts, claim.Opcodes.AddAp)
	appendClaimList(&parts, claim.Opcodes.AddSmall)
	appendClaimList(&parts, claim.Opcodes.AssertEq)
	appendClaimList(&parts, claim.Opcodes.AssertEqImm)
	appendClaimList(&parts, claim.Opcodes.AssertEqDoubleDeref)
	appendClaimList(&parts, claim.Opcodes.Blake)
	appendClaimList(&parts, claim.Opcodes.Call)
	appendClaimList(&parts, claim.Opcodes.CallRelImm)
	appendClaimList(&parts, claim.Opcodes.Generic)
	appendClaimList(&parts, claim.Opcodes.Jnz)
	appendClaimList(&parts, claim.Opcodes.JnzTaken)
	appendClaimList(&parts, claim.Opcodes.Jump)
	appendClaimList(&parts, claim.Opcodes.JumpDoubleDeref)
	appendClaimList(&parts, claim.Opcodes.JumpRel)
	appendClaimList(&parts, claim.Opcodes.JumpRelImm)
	appendClaimList(&parts, claim.Opcodes.Mul)
	appendClaimList(&parts, claim.Opcodes.MulSmall)
	appendClaimList(&parts, claim.Opcodes.Qm31)
	appendClaimList(&parts, claim.Opcodes.Ret)

	// Verify instruction
	appendOptionalClaim(&parts, claim.VerifyInstruction)

	// Blake context
	if ctx := claim.BlakeContext.Claim; ctx != nil {
		appendOptionalClaim(&parts, ctx.BlakeRound)
		appendOptionalClaim(&parts, ctx.BlakeG)
		appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 4}, cairo_components.BlakeRoundSigmaTraceColumns, cairo_components.BlakeRoundSigmaInteractionColumns)
		if ctx.TripleXor32 != nil {
			parts = append(parts, ctx.TripleXor32.LogSizes())
		}
		appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 20}, cairo_components.VerifyBitwiseXor12TraceColumns, cairo_components.VerifyBitwiseXor12InteractionColumns)
	}

	// Builtins
	appendOptionalClaim(&parts, claim.Builtins.AddModBuiltin)
	appendOptionalClaim(&parts, claim.Builtins.BitwiseBuiltin)
	appendOptionalClaim(&parts, claim.Builtins.MulModBuiltin)
	appendOptionalClaim(&parts, claim.Builtins.PedersenBuiltin)
	appendOptionalClaim(&parts, claim.Builtins.PoseidonBuiltin)
	appendOptionalClaim(&parts, claim.Builtins.RangeCheck96)
	appendOptionalClaim(&parts, claim.Builtins.RangeCheck128)

	// Pedersen context
	if pedersen := claim.PedersenContext.Claim; pedersen != nil {
		appendOptionalClaim(&parts, pedersen.PartialEcMul)
		appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 23}, cairo_components.PedersenPointsTableTraceColumns, cairo_components.PedersenPointsTableInteractionColumns)
	}

	// Poseidon context
	if poseidon := claim.PoseidonContext.Claim; poseidon != nil {
		appendOptionalClaim(&parts, poseidon.Poseidon3PartialRoundsChain)
		appendOptionalClaim(&parts, poseidon.PoseidonFullRoundChain)
		appendOptionalClaim(&parts, poseidon.Cube252)
		appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 6}, cairo_components.PoseidonRoundKeysTraceColumns, cairo_components.PoseidonRoundKeysInteractionColumns)
		appendOptionalClaim(&parts, poseidon.RangeCheckFelt252Width27)
	}

	// Memory relations
	parts = append(parts, claim.MemoryAddressToId.LogSizes())
	appendClaimList(&parts, claim.MemoryIDToValue.Big)
	appendOptionalClaim(&parts, claim.MemoryIDToValue.Small)

	// Range checks simple claims.
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 6}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 8}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 11}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 12}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 18}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 19}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 7}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 8}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 9}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 18}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 14}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 18}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 16}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 15}, rangeCheckTraceColumns, rangeCheckInteractionColumns)

	// Verify bitwise XOR components (simple claims).
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 8}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 14}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 16}, rangeCheckTraceColumns, rangeCheckInteractionColumns)
	appendSimpleClaim(&parts, &SimpleLogSizeClaim{LogSize: 18}, rangeCheckTraceColumns, rangeCheckInteractionColumns)

	return cairo_components.ConcatTreeLogSizes(parts...)
}
