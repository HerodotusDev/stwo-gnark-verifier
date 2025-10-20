package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
)

// ╔══════════════════════════════════╗
// ║            Logup Sum             ║
// ╚══════════════════════════════════╝

// LogupSum aggregates logup claimed sums.
func LogupSum(
	qm31Chip *m31.QM31Chip,
	claim variables.CairoClaim,
	elements variables.CairoInteractionElements,
	interactionClaim variables.CairoInteractionClaim,
) m31.QM31 {
	sum := qm31Chip.Zero()

	sum = qm31Chip.Add(sum, sumOpcodeClaims(qm31Chip, interactionClaim.Opcodes))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyInstruction.ClaimedSum)
	sum = qm31Chip.Add(sum, sumBlakeContext(qm31Chip, interactionClaim.BlakeContext))
	sum = qm31Chip.Add(sum, sumBuiltins(qm31Chip, interactionClaim.Builtins))
	sum = qm31Chip.Add(sum, sumPedersenContext(qm31Chip, interactionClaim.PedersenContext))
	sum = qm31Chip.Add(sum, sumPoseidonContext(qm31Chip, interactionClaim.PoseidonContext))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.MemoryAddressToId.ClaimedSum)
	sum = qm31Chip.Add(sum, sumMemoryIDToValue(qm31Chip, interactionClaim.MemoryIDToValue))
	sum = qm31Chip.Add(sum, sumRangeChecks(qm31Chip, interactionClaim.RangeChecks))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor4.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor7.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor8.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor9.ClaimedSum)

	// TODO: incorporate claim.public_data.logup_sum once implemented.
	_ = claim
	_ = elements

	return sum
}

// ╔══════════════════════════════════╗
// ║         Components Sum           ║
// ╚══════════════════════════════════╝

func sumOpcodeClaims(qm31Chip *m31.QM31Chip, claims variables.OpcodeInteractionClaim) m31.QM31 {
	sum := qm31Chip.Zero()

	for _, entry := range claims.Add {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.AddSmall {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.AddAp {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.AssertEq {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.AssertEqImm {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.AssertEqDoubleDeref {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Blake {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Call {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.CallRelImm {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Generic {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Jnz {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.JnzTaken {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Jump {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.JumpDoubleDeref {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.JumpRel {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.JumpRelImm {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Mul {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.MulSmall {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Qm31 {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}
	for _, entry := range claims.Ret {
		sum = addClaimedSum(qm31Chip, sum, entry.ClaimedSum)
	}

	return sum
}

func sumBlakeContext(qm31Chip *m31.QM31Chip, claim variables.BlakeContextInteractionClaim) m31.QM31 {
	if claim.InteractionClaim == nil {
		return qm31Chip.Zero()
	}

	sum := qm31Chip.Zero()
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.BlakeRound.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.BlakeG.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.BlakeRoundSigma.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.TripleXor32.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.VerifyBitwiseXor12.ClaimedSum)
	return sum
}

func sumBuiltins(qm31Chip *m31.QM31Chip, claim variables.BuiltinsInteractionClaim) m31.QM31 {
	sum := qm31Chip.Zero()

	if claim.AddModBuiltin != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.AddModBuiltin.ClaimedSum)
	}
	if claim.BitwiseBuiltin != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.BitwiseBuiltin.ClaimedSum)
	}
	if claim.MulModBuiltin != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.MulModBuiltin.ClaimedSum)
	}
	if claim.PedersenBuiltin != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.PedersenBuiltin.ClaimedSum)
	}
	if claim.PoseidonBuiltin != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.PoseidonBuiltin.ClaimedSum)
	}
	if claim.RangeCheck96 != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.RangeCheck96.ClaimedSum)
	}
	if claim.RangeCheck128 != nil {
		sum = addClaimedSum(qm31Chip, sum, claim.RangeCheck128.ClaimedSum)
	}

	return sum
}

func sumPedersenContext(qm31Chip *m31.QM31Chip, claim variables.PedersenContextInteractionClaim) m31.QM31 {
	if claim.InteractionClaim == nil {
		return qm31Chip.Zero()
	}

	sum := qm31Chip.Zero()
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.PartialEcMul.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.PedersenPointsTable.ClaimedSum)
	return sum
}

func sumPoseidonContext(qm31Chip *m31.QM31Chip, claim variables.PoseidonContextInteractionClaim) m31.QM31 {
	if claim.InteractionClaim == nil {
		return qm31Chip.Zero()
	}

	sum := qm31Chip.Zero()
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.Poseidon3PartialRoundsChain.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.PoseidonFullRoundChain.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.Cube252.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.PoseidonRoundKeys.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.InteractionClaim.RangeCheckFelt252Width27.ClaimedSum)
	return sum
}

func sumMemoryIDToValue(qm31Chip *m31.QM31Chip, claim cairo_components.MemoryIdToValueInteractionClaim) m31.QM31 {
	sum := qm31Chip.Zero()

	for _, entry := range claim.BigClaimedSums {
		sum = addClaimedSum(qm31Chip, sum, entry)
	}
	sum = addClaimedSum(qm31Chip, sum, claim.SmallClaimedSum)
	return sum
}

func sumRangeChecks(qm31Chip *m31.QM31Chip, claim variables.RangeChecksInteractionClaim) m31.QM31 {
	sum := qm31Chip.Zero()
	sum = addClaimedSum(qm31Chip, sum, claim.RC6.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC8.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC11.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC12.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC18.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC19.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC4_3.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC4_4.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC5_4.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC9_9.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC7_2_5.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC3_6_6_3.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC4_4_4_4.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, claim.RC3_3_3_3_3.ClaimedSum)
	return sum
}

// ╔══════════════════════════════════╗
// ║         Helper Functions         ║
// ╚══════════════════════════════════╝

// Adds the normalized claimed sum to the accumulator.
func addClaimedSum(qm31Chip *m31.QM31Chip, acc m31.QM31, value m31.QM31) m31.QM31 {
	return qm31Chip.Add(acc, normalizeQM31(qm31Chip, value))
}

// Returns the claimed sum if it is not nil, otherwise returns zero.
func normalizeQM31(qm31Chip *m31.QM31Chip, value m31.QM31) m31.QM31 {
	components := value.Components()
	for _, comp := range components {
		if comp.Variable() != nil {
			return value
		}
	}
	return qm31Chip.Zero()
}
