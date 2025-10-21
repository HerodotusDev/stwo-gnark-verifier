package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
)

// ╔══════════════════════════════════╗
// ║            Logup Sum             ║
// ╚══════════════════════════════════╝

// LogupSum aggregates logup claimed sums, mirroring Cairo's lookup_sum helper.
func LogupSum(
	qm31Chip *m31.QM31Chip,
	claim variables.CairoClaim,
	elements variables.CairoInteractionElements,
	interactionClaim variables.CairoInteractionClaim,
) m31.QM31 {
	sum := publicDataLogupSum(qm31Chip, elements, claim.PublicData)

	sum = addClaimedSum(qm31Chip, sum, sumOpcodeClaims(qm31Chip, interactionClaim.Opcodes))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyInstruction.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, sumBlakeContext(qm31Chip, interactionClaim.BlakeContext))
	sum = addClaimedSum(qm31Chip, sum, sumBuiltins(qm31Chip, interactionClaim.Builtins))
	sum = addClaimedSum(qm31Chip, sum, sumPedersenContext(qm31Chip, interactionClaim.PedersenContext))
	sum = addClaimedSum(qm31Chip, sum, sumPoseidonContext(qm31Chip, interactionClaim.PoseidonContext))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.MemoryAddressToId.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, sumMemoryIDToValue(qm31Chip, interactionClaim.MemoryIDToValue))
	sum = addClaimedSum(qm31Chip, sum, sumRangeChecks(qm31Chip, interactionClaim.RangeChecks))
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor4.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor7.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor8.ClaimedSum)
	sum = addClaimedSum(qm31Chip, sum, interactionClaim.VerifyBitwiseXor9.ClaimedSum)

	// publicDataLogupSum outputs a reduced sum and sum is incremented 68 times with claimed sums.
	// So 16 * ceil(68 / 16) = 80 bits is a safe bound for the reduction quotient
	sum = qm31Chip.ReduceWithMaxBits(sum, 80)
	return sum
}

// ╔══════════════════════════════════╗
// ║          Component Sums          ║
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

func addClaimedSum(qm31Chip *m31.QM31Chip, acc m31.QM31, value m31.QM31) m31.QM31 {
	return qm31Chip.AddUnchecked(acc, value)
}

// ╔══════════════════════════════════╗
// ║            Public Data           ║
// ╚══════════════════════════════════╝

func publicDataLogupSum(
	qm31Chip *m31.QM31Chip,
	elements variables.CairoInteractionElements,
	publicData variables.PublicData,
) m31.QM31 {
	sum := qm31Chip.Zero()
	entries := publicMemoryEntries(qm31Chip, publicData)

	for _, entry := range entries {
		address := m31.NewQM31FromM31(entry.Address)
		id := m31.NewQM31FromM31(entry.ID)

		addrToID := combineAndInverse(qm31Chip, elements.MemoryAddressToId, []m31.QM31{address, id})

		values := make([]m31.QM31, 1+variables.NM31InFelt252)
		values[0] = id
		for i, limb := range entry.Value {
			values[i+1] = m31.NewQM31FromM31(limb)
		}
		idToValue := combineAndInverse(qm31Chip, elements.MemoryIDToValue, values)

		sum = qm31Chip.Add(sum, qm31Chip.Add(addrToID, idToValue))
	}

	finalInputs := []m31.QM31{
		m31.NewQM31FromM31(publicData.FinalState.PC),
		m31.NewQM31FromM31(publicData.FinalState.AP),
		m31.NewQM31FromM31(publicData.FinalState.FP),
	}
	sum = qm31Chip.Add(sum, combineAndInverse(qm31Chip, elements.Opcodes, finalInputs))

	initialInputs := []m31.QM31{
		m31.NewQM31FromM31(publicData.InitialState.PC),
		m31.NewQM31FromM31(publicData.InitialState.AP),
		m31.NewQM31FromM31(publicData.InitialState.FP),
	}
	sum = qm31Chip.Sub(sum, combineAndInverse(qm31Chip, elements.Opcodes, initialInputs))

	return sum
}

func publicMemoryEntries(qm31Chip *m31.QM31Chip, publicData variables.PublicData) []variables.PublicMemoryEntry {
	m31Chip := qm31Chip.M31Chip()

	programLen := len(publicData.PublicMemory.Program)
	outputLen := len(publicData.PublicMemory.Output)
	safeCallLen := len(publicData.PublicMemory.SafeCall)
	segments := presentSegments(publicData.PublicMemory.PublicSegments)
	requiredCapacity := programLen + outputLen + safeCallLen + len(segments)*2

	entries := make([]variables.PublicMemoryEntry, 0, requiredCapacity)

	// Program entries
	for i, cell := range publicData.PublicMemory.Program {
		entries = append(entries, variables.PublicMemoryEntry{
			Address: m31Chip.Add(publicData.InitialState.PC, m31.NewM31Unchecked(i)),
			ID:      cell.ID,
			Value:   cell.Value,
		})
	}

	// Output entries
	for i, cell := range publicData.PublicMemory.Output {
		entries = append(entries, variables.PublicMemoryEntry{
			Address: m31Chip.Add(publicData.FinalState.AP, m31.NewM31Unchecked(i)),
			ID:      cell.ID,
			Value:   cell.Value,
		})
	}

	// Safe call entries
	safeCall := publicData.PublicMemory.SafeCall
	entries = append(entries, variables.PublicMemoryEntry{
		Address: m31Chip.Sub(publicData.InitialState.AP, m31.NewM31Unchecked(2)),
		ID:      safeCall[0].ID,
		Value:   safeCall[0].Value,
	})

	entries = append(entries, variables.PublicMemoryEntry{
		Address: m31Chip.Sub(publicData.InitialState.AP, m31.NewM31Unchecked(1)),
		ID:      safeCall[1].ID,
		Value:   safeCall[1].Value,
	})

	// Segment ranges entries
	finalBase := m31Chip.Sub(publicData.FinalState.AP, m31.NewM31Unchecked(len(segments)))
	for i, segment := range segments {
		entries = append(entries, variables.PublicMemoryEntry{
			Address: m31Chip.Add(publicData.InitialState.AP, m31.NewM31Unchecked(i)),
			ID:      segment.StartPtr.ID,
			Value:   segment.StartPtr.Value,
		})

		entries = append(entries, variables.PublicMemoryEntry{
			Address: m31Chip.Add(finalBase, m31.NewM31Unchecked(i)),
			ID:      segment.StopPtr.ID,
			Value:   segment.StopPtr.Value,
		})
	}

	return entries
}

func presentSegments(ranges variables.PublicSegmentRanges) []variables.SegmentRange {
	segments := make([]variables.SegmentRange, 0, 11)

	appendIfPresent := func(segment *variables.SegmentRange) {
		if segment != nil {
			segments = append(segments, *segment)
		}
	}

	segments = append(segments, ranges.Output)
	appendIfPresent(ranges.Pedersen)
	appendIfPresent(ranges.RangeCheck128)
	appendIfPresent(ranges.Ecdsa)
	appendIfPresent(ranges.Bitwise)
	appendIfPresent(ranges.EcOp)
	appendIfPresent(ranges.Keccak)
	appendIfPresent(ranges.Poseidon)
	appendIfPresent(ranges.RangeCheck96)
	appendIfPresent(ranges.AddMod)
	appendIfPresent(ranges.MulMod)

	return segments
}

func combineAndInverse(qm31Chip *m31.QM31Chip, elements m31.InteractionElements, inputs []m31.QM31) m31.QM31 {
	combined, err := qm31Chip.Combine(elements, inputs)
	if err != nil {
		panic(err)
	}
	return qm31Chip.Inverse(combined)
}
