package components

import (
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
	circuitData variables.CircuitData,
) m31.QM31 {
	// Public data sum
	sum := publicDataLogupSum(qm31Chip, elements, claim.PublicData, circuitData)

	// Opcode sums
	if circuitData.ComponentConfig[0] {
		sum = qm31Chip.Add(sum, interactionClaim.AddAp.ClaimedSum)
	}

	if circuitData.ComponentConfig[1] {
		sum = qm31Chip.Add(sum, interactionClaim.Add.ClaimedSum)
	}

	if circuitData.ComponentConfig[2] {
		sum = qm31Chip.Add(sum, interactionClaim.AddSmall.ClaimedSum)
	}

	if circuitData.ComponentConfig[3] {
		sum = qm31Chip.Add(sum, interactionClaim.AssertEq.ClaimedSum)
	}

	if circuitData.ComponentConfig[4] {
		sum = qm31Chip.Add(sum, interactionClaim.AssertEqImm.ClaimedSum)
	}

	if circuitData.ComponentConfig[5] {
		sum = qm31Chip.Add(sum, interactionClaim.AssertEqDoubleDeref.ClaimedSum)
	}

	if circuitData.ComponentConfig[6] {
		sum = qm31Chip.Add(sum, interactionClaim.Blake.ClaimedSum)
	}

	if circuitData.ComponentConfig[7] {
		sum = qm31Chip.Add(sum, interactionClaim.Call.ClaimedSum)
	}

	if circuitData.ComponentConfig[8] {
		sum = qm31Chip.Add(sum, interactionClaim.CallRelImm.ClaimedSum)
	}

	if circuitData.ComponentConfig[9] {
		sum = qm31Chip.Add(sum, interactionClaim.Generic.ClaimedSum)
	}

	if circuitData.ComponentConfig[10] {
		sum = qm31Chip.Add(sum, interactionClaim.Jnz.ClaimedSum)
	}

	if circuitData.ComponentConfig[11] {
		sum = qm31Chip.Add(sum, interactionClaim.JnzTaken.ClaimedSum)
	}

	if circuitData.ComponentConfig[12] {
		sum = qm31Chip.Add(sum, interactionClaim.Jump.ClaimedSum)
	}

	if circuitData.ComponentConfig[13] {
		sum = qm31Chip.Add(sum, interactionClaim.JumpDoubleDeref.ClaimedSum)
	}

	if circuitData.ComponentConfig[14] {
		sum = qm31Chip.Add(sum, interactionClaim.JumpRel.ClaimedSum)
	}

	if circuitData.ComponentConfig[15] {
		sum = qm31Chip.Add(sum, interactionClaim.JumpRelImm.ClaimedSum)
	}

	if circuitData.ComponentConfig[16] {
		sum = qm31Chip.Add(sum, interactionClaim.Mul.ClaimedSum)
	}

	if circuitData.ComponentConfig[17] {
		sum = qm31Chip.Add(sum, interactionClaim.MulSmall.ClaimedSum)
	}

	if circuitData.ComponentConfig[18] {
		sum = qm31Chip.Add(sum, interactionClaim.Qm31.ClaimedSum)
	}

	if circuitData.ComponentConfig[19] {
		sum = qm31Chip.Add(sum, interactionClaim.Ret.ClaimedSum)
	}

	// Verify instruction sum
	if circuitData.ComponentConfig[20] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyInstruction.ClaimedSum)
	}

	// Blake context sums
	if circuitData.ComponentConfig[21] {
		sum = qm31Chip.Add(sum, interactionClaim.BlakeRound.ClaimedSum)
	}

	if circuitData.ComponentConfig[22] {
		sum = qm31Chip.Add(sum, interactionClaim.BlakeG.ClaimedSum)
	}

	if circuitData.ComponentConfig[23] {
		sum = qm31Chip.Add(sum, interactionClaim.BlakeRoundSigma.ClaimedSum)
	}

	if circuitData.ComponentConfig[24] {
		sum = qm31Chip.Add(sum, interactionClaim.TripleXor32.ClaimedSum)
	}

	if circuitData.ComponentConfig[25] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyBitwiseXor12.ClaimedSum)
	}

	// Builtins sums
	if circuitData.ComponentConfig[26] {
		sum = qm31Chip.Add(sum, interactionClaim.AddModBuiltin.ClaimedSum)
	}

	if circuitData.ComponentConfig[27] {
		sum = qm31Chip.Add(sum, interactionClaim.BitwiseBuiltin.ClaimedSum)
	}
	if circuitData.ComponentConfig[28] {
		sum = qm31Chip.Add(sum, interactionClaim.MulModBuiltin.ClaimedSum)
	}
	if circuitData.ComponentConfig[29] {
		sum = qm31Chip.Add(sum, interactionClaim.PedersenBuiltin.ClaimedSum)
	}
	if circuitData.ComponentConfig[30] {
		sum = qm31Chip.Add(sum, interactionClaim.PoseidonBuiltin.ClaimedSum)
	}
	if circuitData.ComponentConfig[31] {
		sum = qm31Chip.Add(sum, interactionClaim.RangeCheck96.ClaimedSum)
	}
	if circuitData.ComponentConfig[32] {
		sum = qm31Chip.Add(sum, interactionClaim.RangeCheck128.ClaimedSum)
	}

	// Pedersen context sums
	if circuitData.ComponentConfig[33] {
		sum = qm31Chip.Add(sum, interactionClaim.PartialEcMul.ClaimedSum)
	}

	if circuitData.ComponentConfig[34] {
		sum = qm31Chip.Add(sum, interactionClaim.PedersenPointsTable.ClaimedSum)
	}

	// Poseidon context sums
	if circuitData.ComponentConfig[35] {
		sum = qm31Chip.Add(sum, interactionClaim.Poseidon3PartialRoundsChain.ClaimedSum)
	}
	if circuitData.ComponentConfig[36] {
		sum = qm31Chip.Add(sum, interactionClaim.PoseidonFullRoundChain.ClaimedSum)
	}
	if circuitData.ComponentConfig[37] {
		sum = qm31Chip.Add(sum, interactionClaim.Cube252.ClaimedSum)
	}
	if circuitData.ComponentConfig[38] {
		sum = qm31Chip.Add(sum, interactionClaim.PoseidonRoundKeys.ClaimedSum)
	}
	if circuitData.ComponentConfig[39] {
		sum = qm31Chip.Add(sum, interactionClaim.RangeCheckFelt252Width27.ClaimedSum)
	}

	// Memory relations sums
	if circuitData.ComponentConfig[40] {
		sum = qm31Chip.Add(sum, interactionClaim.MemoryAddressToID.ClaimedSum)
	}
	if circuitData.ComponentConfig[41] {
		sum = qm31Chip.Add(sum, interactionClaim.MemoryIDToBigBig.ClaimedSum)
	}
	if circuitData.ComponentConfig[42] {
		sum = qm31Chip.Add(sum, interactionClaim.MemoryIDToBigSmall.ClaimedSum)
	}

	// Range checks sums
	if circuitData.ComponentConfig[43] {
		sum = qm31Chip.Add(sum, interactionClaim.RC6.ClaimedSum)
	}
	if circuitData.ComponentConfig[44] {
		sum = qm31Chip.Add(sum, interactionClaim.RC8.ClaimedSum)
	}
	if circuitData.ComponentConfig[45] {
		sum = qm31Chip.Add(sum, interactionClaim.RC11.ClaimedSum)
	}
	if circuitData.ComponentConfig[46] {
		sum = qm31Chip.Add(sum, interactionClaim.RC12.ClaimedSum)
	}
	if circuitData.ComponentConfig[47] {
		sum = qm31Chip.Add(sum, interactionClaim.RC18.ClaimedSum)
	}
	if circuitData.ComponentConfig[48] {
		sum = qm31Chip.Add(sum, interactionClaim.RC19.ClaimedSum)
	}
	if circuitData.ComponentConfig[49] {
		sum = qm31Chip.Add(sum, interactionClaim.RC43.ClaimedSum)
	}
	if circuitData.ComponentConfig[50] {
		sum = qm31Chip.Add(sum, interactionClaim.RC44.ClaimedSum)
	}
	if circuitData.ComponentConfig[51] {
		sum = qm31Chip.Add(sum, interactionClaim.RC54.ClaimedSum)
	}
	if circuitData.ComponentConfig[52] {
		sum = qm31Chip.Add(sum, interactionClaim.RC99.ClaimedSum)
	}
	if circuitData.ComponentConfig[53] {
		sum = qm31Chip.Add(sum, interactionClaim.RC725.ClaimedSum)
	}
	if circuitData.ComponentConfig[54] {
		sum = qm31Chip.Add(sum, interactionClaim.RC3663.ClaimedSum)
	}
	if circuitData.ComponentConfig[55] {
		sum = qm31Chip.Add(sum, interactionClaim.RC4444.ClaimedSum)
	}
	if circuitData.ComponentConfig[56] {
		sum = qm31Chip.Add(sum, interactionClaim.RC33333.ClaimedSum)
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyBitwiseXor4.ClaimedSum)
	}
	if circuitData.ComponentConfig[58] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyBitwiseXor7.ClaimedSum)
	}
	if circuitData.ComponentConfig[59] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyBitwiseXor8.ClaimedSum)
	}
	if circuitData.ComponentConfig[60] {
		sum = qm31Chip.Add(sum, interactionClaim.VerifyBitwiseXor9.ClaimedSum)
	}

	// publicDataLogupSum outputs a reduced sum and sum is incremented 68 times with claimed sums.
	// So 16 * ceil(68 / 16) = 80 bits is a safe bound for the reduction quotient
	sum = qm31Chip.ReduceWithMaxBits(sum, 80)
	return sum
}

// ╔══════════════════════════════════╗
// ║            Public Data           ║
// ╚══════════════════════════════════╝

func publicDataLogupSum(
	qm31Chip *m31.QM31Chip,
	elements variables.CairoInteractionElements,
	publicData variables.PublicData,
	circuitData variables.CircuitData,
) m31.QM31 {
	sum := qm31Chip.Zero()
	entries := publicMemoryEntries(qm31Chip, publicData, circuitData)

	for _, entry := range entries {
		address := m31.NewQM31FromM31(entry.Address)
		id := m31.NewQM31FromM31(entry.ID)

		addrToID := combineAndInverse(qm31Chip, elements.MemoryAddressToID, []m31.QM31{address, id})

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

func publicMemoryEntries(qm31Chip *m31.QM31Chip, publicData variables.PublicData, circuitData variables.CircuitData) []variables.PublicMemoryEntry {
	m31Chip := qm31Chip.M31Chip()

	programLen := len(publicData.PublicMemory.Program)
	outputLen := len(publicData.PublicMemory.Output)
	safeCallLen := len(publicData.PublicMemory.SafeCall)
	segments := publicData.PublicMemory.PublicSegments.PresentSegments(circuitData)
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

func combineAndInverse(qm31Chip *m31.QM31Chip, elements m31.InteractionElements, inputs []m31.QM31) m31.QM31 {
	combined, err := qm31Chip.Combine(elements, inputs)
	if err != nil {
		panic(err)
	}
	return qm31Chip.Inverse(combined)
}
