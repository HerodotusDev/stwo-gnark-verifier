package variables

import (
	"encoding/json"
	"io"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║          Proof Reading           ║
// ╚══════════════════════════════════╝

// ReadCairoProof loads a Cairo proof from the given path.
func ReadCairoProof(path string) (*ProofRaw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return ReadCairoProofFromReader(file)
}

// ReadCairoProofFromReader decodes a Cairo proof from the supplied reader.
func ReadCairoProofFromReader(r io.Reader) (*ProofRaw, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var proof ProofRaw
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}

	return &proof, nil
}

// ╔══════════════════════════════════╗
// ║           Proof Building         ║
// ╚══════════════════════════════════╝

// BuildProof builds a StarkProof (used in circuits) from a ProofRaw (from json)
func BuildProof(proofRaw *ProofRaw) *StarkProof {
	if proofRaw == nil {
		return nil
	}

	var proof StarkProof

	proof.Claim = BuildClaim(&proofRaw.Claim)
	proof.InteractionClaims = BuildInteractionClaims(&proofRaw.InteractionClaim)

	// TODO: Build StarkProof from StarkProofRaw

	return &proof
}

// BuildClaim builds a CairoClaim from a ClaimRaw
func BuildClaim(claimRaw *ClaimRaw) CairoClaim {
	if claimRaw == nil {
		return CairoClaim{}
	}

	var claim CairoClaim

	claim.MemoryAddressToId = cairo_components.MemoryAddressToIdClaim{LogSize: uints.NewU8(uint8(claimRaw.MemoryAddressToId.LogSize))}

	return claim
}

// BuildInteractionClaims builds a CairoInteractionClaim from a InteractionClaimRaw
func BuildInteractionClaims(interactionClaimRaw *InteractionClaimRaw) CairoInteractionClaim {
	if interactionClaimRaw == nil {
		return CairoInteractionClaim{}
	}

	var interactionClaim CairoInteractionClaim

	// Opcode interaction claim
	interactionClaim.Opcodes = buildOpcodeInteractionClaim(interactionClaimRaw.Opcodes)

	// Verify instruction interaction claim
	if sum, ok := qm31FromUint64Grid(interactionClaimRaw.VerifyInstruction.ClaimedSum); ok {
		interactionClaim.VerifyInstruction = cairo_components.VerifyInstructionInteractionClaim{ClaimedSum: sum}
	}

	// Blake context interaction claim
	interactionClaim.BlakeContext = buildBlakeContextInteractionClaim(interactionClaimRaw.BlakeContext)

	// Builtins interaction claim
	interactionClaim.Builtins = buildBuiltinsInteractionClaim(interactionClaimRaw.Builtins)

	// Pedersen context interaction claim
	interactionClaim.PedersenContext = buildPedersenContextInteractionClaim(interactionClaimRaw.PedersenContext)

	// Poseidon context interaction claim
	interactionClaim.PoseidonContext = buildPoseidonContextInteractionClaim(interactionClaimRaw.PoseidonContext)

	// Memory address to id interaction claim
	if sum, ok := qm31FromUint64Grid(interactionClaimRaw.MemoryAddressToId.ClaimedSum); ok {
		interactionClaim.MemoryAddressToId = cairo_components.MemoryAddressToIdInteractionClaim{ClaimedSum: sum}
	}

	// Memory ID to value interaction claim
	interactionClaim.MemoryIDToValue = buildMemoryIdToValueInteractionClaim(interactionClaimRaw.MemoryIDToValue)

	// Range checks interaction claim
	interactionClaim.RangeChecks = buildRangeChecksInteractionClaim(interactionClaimRaw.RangeChecks)

	// Verify Bitwise Xor interaction claims
	if sum, ok := qm31FromUint64Pairs(interactionClaimRaw.VerifyBitwiseXor4.ClaimedSum); ok {
		interactionClaim.VerifyBitwiseXor4 = cairo_components.VerifyBitwiseXor4InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := qm31FromUint64Pairs(interactionClaimRaw.VerifyBitwiseXor7.ClaimedSum); ok {
		interactionClaim.VerifyBitwiseXor7 = cairo_components.VerifyBitwiseXor7InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := qm31FromUint64Pairs(interactionClaimRaw.VerifyBitwiseXor8.ClaimedSum); ok {
		interactionClaim.VerifyBitwiseXor8 = cairo_components.VerifyBitwiseXor8InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := qm31FromUint64Pairs(interactionClaimRaw.VerifyBitwiseXor9.ClaimedSum); ok {
		interactionClaim.VerifyBitwiseXor9 = cairo_components.VerifyBitwiseXor9InteractionClaim{ClaimedSum: sum}
	}

	return interactionClaim
}

func buildOpcodeInteractionClaim(raw map[string][]OpcodeInteractionEntryRaw) OpcodeInteractionClaim {
	var claim OpcodeInteractionClaim
	if raw == nil {
		return claim
	}

	claim.Add = mapOpcodeEntries(raw["add"], func(sum m31.QM31) cairo_components.AddOpcodeInteractionClaim {
		return cairo_components.AddOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.AddSmall = mapOpcodeEntries(raw["add_small"], func(sum m31.QM31) cairo_components.AddSmallOpcodeInteractionClaim {
		return cairo_components.AddSmallOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.AddAp = mapOpcodeEntries(raw["add_ap"], func(sum m31.QM31) cairo_components.AddApOpcodeInteractionClaim {
		return cairo_components.AddApOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.AssertEq = mapOpcodeEntries(raw["assert_eq"], func(sum m31.QM31) cairo_components.AssertEqOpcodeInteractionClaim {
		return cairo_components.AssertEqOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.AssertEqImm = mapOpcodeEntries(raw["assert_eq_imm"], func(sum m31.QM31) cairo_components.AssertEqImmOpcodeInteractionClaim {
		return cairo_components.AssertEqImmOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.AssertEqDoubleDeref = mapOpcodeEntries(raw["assert_eq_double_deref"], func(sum m31.QM31) cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim {
		return cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Blake = mapOpcodeEntries(raw["blake"], func(sum m31.QM31) cairo_components.BlakeOpcodeInteractionClaim {
		return cairo_components.BlakeOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Call = mapOpcodeEntries(raw["call"], func(sum m31.QM31) cairo_components.CallOpcodeInteractionClaim {
		return cairo_components.CallOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.CallRelImm = mapOpcodeEntries(raw["call_rel_imm"], func(sum m31.QM31) cairo_components.CallRelImmOpcodeInteractionClaim {
		return cairo_components.CallRelImmOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Generic = mapOpcodeEntries(raw["generic"], func(sum m31.QM31) cairo_components.GenericOpcodeInteractionClaim {
		return cairo_components.GenericOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Jnz = mapOpcodeEntries(raw["jnz"], func(sum m31.QM31) cairo_components.JnzOpcodeInteractionClaim {
		return cairo_components.JnzOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.JnzTaken = mapOpcodeEntries(raw["jnz_taken"], func(sum m31.QM31) cairo_components.JnzTakenOpcodeInteractionClaim {
		return cairo_components.JnzTakenOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Jump = mapOpcodeEntries(raw["jump"], func(sum m31.QM31) cairo_components.JumpOpcodeInteractionClaim {
		return cairo_components.JumpOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.JumpDoubleDeref = mapOpcodeEntries(raw["jump_double_deref"], func(sum m31.QM31) cairo_components.JumpDoubleDerefOpcodeInteractionClaim {
		return cairo_components.JumpDoubleDerefOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.JumpRel = mapOpcodeEntries(raw["jump_rel"], func(sum m31.QM31) cairo_components.JumpRelOpcodeInteractionClaim {
		return cairo_components.JumpRelOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.JumpRelImm = mapOpcodeEntries(raw["jump_rel_imm"], func(sum m31.QM31) cairo_components.JumpRelImmOpcodeInteractionClaim {
		return cairo_components.JumpRelImmOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Mul = mapOpcodeEntries(raw["mul"], func(sum m31.QM31) cairo_components.MulOpcodeInteractionClaim {
		return cairo_components.MulOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.MulSmall = mapOpcodeEntries(raw["mul_small"], func(sum m31.QM31) cairo_components.MulSmallOpcodeInteractionClaim {
		return cairo_components.MulSmallOpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Qm31 = mapOpcodeEntries(raw["qm31"], func(sum m31.QM31) cairo_components.Qm31OpcodeInteractionClaim {
		return cairo_components.Qm31OpcodeInteractionClaim{ClaimedSum: sum}
	})
	claim.Ret = mapOpcodeEntries(raw["ret"], func(sum m31.QM31) cairo_components.RetOpcodeInteractionClaim {
		return cairo_components.RetOpcodeInteractionClaim{ClaimedSum: sum}
	})

	return claim
}

func buildBlakeContextInteractionClaim(raw BlakeContextInteractionClaimRaw) BlakeContextInteractionClaim {
	if raw.Claim == nil {
		return BlakeContextInteractionClaim{}
	}

	var (
		interaction BlakeInteractionClaim
		hasData     bool
	)

	if sum, ok := componentClaimToQM31(raw.Claim.BlakeRound); ok {
		interaction.BlakeRound = cairo_components.BlakeRoundInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.BlakeG); ok {
		interaction.BlakeG = cairo_components.BlakeGInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.BlakeSigma); ok {
		interaction.BlakeRoundSigma = cairo_components.BlakeRoundSigmaInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.TripleXor32); ok {
		interaction.TripleXor32 = cairo_components.TripleXor32InteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.VerifyBitwiseXor12); ok {
		interaction.VerifyBitwiseXor12 = cairo_components.VerifyBitwiseXor12InteractionClaim{ClaimedSum: sum}
		hasData = true
	}

	if !hasData {
		return BlakeContextInteractionClaim{}
	}

	return BlakeContextInteractionClaim{
		InteractionClaim: &interaction,
	}
}

func buildBuiltinsInteractionClaim(raw BuiltinsInteractionClaimRaw) BuiltinsInteractionClaim {
	var claim BuiltinsInteractionClaim
	if raw == nil {
		return claim
	}

	if sum, ok := componentClaimToQM31(raw["add_mod_builtin"]); ok {
		claim.AddModBuiltin = &cairo_components.AddModBuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["bitwise_builtin"]); ok {
		claim.BitwiseBuiltin = &cairo_components.BitwiseBuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["mul_mod_builtin"]); ok {
		claim.MulModBuiltin = &cairo_components.MulModBuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["pedersen_builtin"]); ok {
		claim.PedersenBuiltin = &cairo_components.PedersenBuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["poseidon_builtin"]); ok {
		claim.PoseidonBuiltin = &cairo_components.PoseidonBuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["range_check_96_builtin"]); ok {
		claim.RangeCheck96 = &cairo_components.RangeCheck96BuiltinInteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["range_check_128_builtin"]); ok {
		claim.RangeCheck128 = &cairo_components.RangeCheck128BuiltinInteractionClaim{ClaimedSum: sum}
	}

	return claim
}

func buildPedersenContextInteractionClaim(raw PedersenContextInteractionClaimRaw) PedersenContextInteractionClaim {
	if raw.Claim == nil {
		return PedersenContextInteractionClaim{}
	}

	var (
		interaction PedersenInteractionClaim
		hasData     bool
	)

	if sum, ok := componentClaimToQM31(raw.Claim["partial_ec_mul"]); ok {
		interaction.PartialEcMul = cairo_components.PartialEcMulInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim["pedersen_points_table"]); ok {
		interaction.PedersenPointsTable = cairo_components.PedersenPointsTableInteractionClaim{ClaimedSum: sum}
		hasData = true
	}

	if !hasData {
		return PedersenContextInteractionClaim{}
	}

	return PedersenContextInteractionClaim{InteractionClaim: &interaction}
}

func buildPoseidonContextInteractionClaim(raw PoseidonContextInteractionClaimRaw) PoseidonContextInteractionClaim {
	if raw.Claim == nil {
		return PoseidonContextInteractionClaim{}
	}

	var (
		interaction PoseidonInteractionClaim
		hasData     bool
	)

	if sum, ok := componentClaimToQM31(raw.Claim.Poseidon3PartialRoundsChain); ok {
		interaction.Poseidon3PartialRoundsChain = cairo_components.Poseidon3PartialRoundsChainInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.PoseidonFullRoundChain); ok {
		interaction.PoseidonFullRoundChain = cairo_components.PoseidonFullRoundChainInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.Cube252); ok {
		interaction.Cube252 = cairo_components.Cube252InteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.PoseidonRoundKeys); ok {
		interaction.PoseidonRoundKeys = cairo_components.PoseidonRoundKeysInteractionClaim{ClaimedSum: sum}
		hasData = true
	}
	if sum, ok := componentClaimToQM31(raw.Claim.RangeCheckFelt252Width27); ok {
		interaction.RangeCheckFelt252Width27 = cairo_components.RangeCheckFelt252Width27InteractionClaim{ClaimedSum: sum}
		hasData = true
	}

	if !hasData {
		return PoseidonContextInteractionClaim{}
	}

	return PoseidonContextInteractionClaim{InteractionClaim: &interaction}
}

func buildMemoryIdToValueInteractionClaim(raw MemoryIDToValueInteractionClaimRaw) cairo_components.MemoryIdToValueInteractionClaim {
	bigSums := make([]m31.QM31, 0, len(raw.BigClaimedSums))
	for _, entry := range raw.BigClaimedSums {
		if sum, ok := qm31FromUint64Pairs(entry); ok {
			bigSums = append(bigSums, sum)
		}
	}

	var smallSum m31.QM31
	if sum, ok := qm31FromUint64Pairs(raw.SmallClaimedSum); ok {
		smallSum = sum
	}

	return cairo_components.MemoryIdToValueInteractionClaim{
		BigClaimedSums:  bigSums,
		SmallClaimedSum: smallSum,
	}
}

func buildRangeChecksInteractionClaim(raw RangeChecksInteractionClaimRaw) RangeChecksInteractionClaim {
	var claim RangeChecksInteractionClaim

	if sum, ok := componentClaimToQM31(raw["rc_6"]); ok {
		claim.RC6 = cairo_components.RangeCheck6InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_8"]); ok {
		claim.RC8 = cairo_components.RangeCheck8InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_11"]); ok {
		claim.RC11 = cairo_components.RangeCheck11InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_12"]); ok {
		claim.RC12 = cairo_components.RangeCheck12InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_18"]); ok {
		claim.RC18 = cairo_components.RangeCheck18InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_19"]); ok {
		claim.RC19 = cairo_components.RangeCheck19InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_4_3"]); ok {
		claim.RC4_3 = cairo_components.RangeCheck4_3InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_4_4"]); ok {
		claim.RC4_4 = cairo_components.RangeCheck4_4InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_5_4"]); ok {
		claim.RC5_4 = cairo_components.RangeCheck5_4InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_9_9"]); ok {
		claim.RC9_9 = cairo_components.RangeCheck9_9InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_7_2_5"]); ok {
		claim.RC7_2_5 = cairo_components.RangeCheck7_2_5InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_3_6_6_3"]); ok {
		claim.RC3_6_6_3 = cairo_components.RangeCheck3_6_6_3InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_4_4_4_4"]); ok {
		claim.RC4_4_4_4 = cairo_components.RangeCheck4_4_4_4InteractionClaim{ClaimedSum: sum}
	}
	if sum, ok := componentClaimToQM31(raw["rc_3_3_3_3_3"]); ok {
		claim.RC3_3_3_3_3 = cairo_components.RangeCheck3_3_3_3_3InteractionClaim{ClaimedSum: sum}
	}

	return claim
}

// ╔══════════════════════════════════╗
// ║         Helper functions         ║
// ╚══════════════════════════════════╝

// qm31FromUint64Grid converts a 2x2 uint64 grid into a QM31 if the layout is valid.
func qm31FromUint64Grid(grid [][]uint64) (m31.QM31, bool) {
	if len(grid) < 2 {
		return m31.QM31{}, false
	}
	if len(grid[0]) < 2 || len(grid[1]) < 2 {
		return m31.QM31{}, false
	}
	return m31.NewQM31FromArrays(grid), true
}

// qm31FromUint64Pairs converts an array of two limb pairs into a QM31 element.
func qm31FromUint64Pairs(pairs [][2]uint64) (m31.QM31, bool) {
	if len(pairs) < 2 {
		return m31.QM31{}, false
	}

	grid := make([][]uint64, 2)
	for i := 0; i < 2; i++ {
		grid[i] = []uint64{pairs[i][0], pairs[i][1]}
	}

	return m31.NewQM31FromArrays(grid), true
}

// componentClaimToQM31 safely unpacks a nullable component claim entry.
func componentClaimToQM31(entry *ComponentClaimedSumEntry) (m31.QM31, bool) {
	if entry == nil {
		return m31.QM31{}, false
	}
	return qm31FromUint64Pairs(entry.ClaimedSum)
}

// mapOpcodeEntries decodes raw opcode claimed sums and wraps them in the supplied struct factory.
func mapOpcodeEntries[T any](entries []OpcodeInteractionEntryRaw, wrap func(m31.QM31) T) []T {
	if len(entries) == 0 {
		return nil
	}

	result := make([]T, 0, len(entries))
	for _, entry := range entries {
		if sum, ok := qm31FromUint64Grid(entry.ClaimedSum); ok {
			result = append(result, wrap(sum))
		}
	}

	return result
}
