package variables

import (
	"encoding/json"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"

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

// BuildProof builds a Proof (used in circuits) from a ProofRaw (from json)
func BuildProof(proofRaw *ProofRaw) *Proof {
	if proofRaw == nil {
		return nil
	}

	var proof Proof

	proof.Claim = BuildClaim(&proofRaw.Claim)
	proof.InteractionClaim = BuildInteractionClaim(&proofRaw.InteractionClaim)
	proof.StarkProof = BuildStarkProof(&proofRaw.StarkProof)

	return &proof
}

// ╔══════════════════════════════════╗
// ║         Claim Building           ║
// ╚══════════════════════════════════╝

// BuildClaim builds a CairoClaim from a ClaimRaw
func BuildClaim(claimRaw *ClaimRaw) CairoClaim {
	if claimRaw == nil {
		return CairoClaim{}
	}

	memAddrLogSize := uint8FromUint64(claimRaw.MemoryAddressToId.LogSize)
	claim := CairoClaim{
		PublicData: ConstructPublicData(&claimRaw.PublicData),
		MemoryAddressToId: cairo_components.MemoryAddressToIdClaim{
			LogSize: uints.NewU8(memAddrLogSize),
		},
	}

	claim.Opcodes = buildOpcodeClaims(claimRaw.Opcodes)
	if verifyInstructionLogSize := claimRaw.VerifyInstruction.LogSize; verifyInstructionLogSize > 0 {
		claim.VerifyInstruction = &cairo_components.VerifyInstructionClaim{
			LogSize: uints.NewU8(uint8FromUint64(verifyInstructionLogSize)),
		}
	}
	claim.BlakeContext = buildBlakeContextClaim(claimRaw.BlakeContext)
	claim.Builtins = buildBuiltinsClaim(claimRaw.Builtins)
	claim.PedersenContext = buildPedersenContextClaim(claimRaw.PedersenContext)
	claim.PoseidonContext = buildPoseidonContextClaim(claimRaw.PoseidonContext)
	claim.MemoryIDToValue = buildMemoryIDToValueClaim(claimRaw.MemoryIDToValue)
	claim.RangeChecks = buildRangeChecksClaim(claimRaw.RangeChecks)
	claim.VerifyBitwiseXor4 = buildVerifyBitwiseXorClaim(claimRaw.VerifyBitwiseXor4)
	claim.VerifyBitwiseXor7 = buildVerifyBitwiseXorClaim(claimRaw.VerifyBitwiseXor7)
	claim.VerifyBitwiseXor8 = buildVerifyBitwiseXorClaim(claimRaw.VerifyBitwiseXor8)
	claim.VerifyBitwiseXor9 = buildVerifyBitwiseXorClaim(claimRaw.VerifyBitwiseXor9)

	return claim
}

func buildOpcodeClaims(raw OpcodeClaimRaw) OpcodeClaims {
	var claims OpcodeClaims

	claims.Add = mapOpcodeClaimEntries(raw.Add, func(logSize uint32) cairo_components.AddOpcodeClaim {
		return cairo_components.AddOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.AddSmall = mapOpcodeClaimEntries(raw.AddSmall, func(logSize uint32) cairo_components.AddSmallOpcodeClaim {
		return cairo_components.AddSmallOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.AddAp = mapOpcodeClaimEntries(raw.AddAp, func(logSize uint32) cairo_components.AddApOpcodeClaim {
		return cairo_components.AddApOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.AssertEq = mapOpcodeClaimEntries(raw.AssertEq, func(logSize uint32) cairo_components.AssertEqOpcodeClaim {
		return cairo_components.AssertEqOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.AssertEqImm = mapOpcodeClaimEntries(raw.AssertEqImm, func(logSize uint32) cairo_components.AssertEqImmOpcodeClaim {
		return cairo_components.AssertEqImmOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.AssertEqDoubleDeref = mapOpcodeClaimEntries(raw.AssertEqDoubleDeref, func(logSize uint32) cairo_components.AssertEqDoubleDerefOpcodeClaim {
		return cairo_components.AssertEqDoubleDerefOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Blake = mapOpcodeClaimEntries(raw.Blake, func(logSize uint32) cairo_components.BlakeCompressOpcodeClaim {
		return cairo_components.BlakeCompressOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Call = mapOpcodeClaimEntries(raw.Call, func(logSize uint32) cairo_components.CallOpcodeClaim {
		return cairo_components.CallOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.CallRelImm = mapOpcodeClaimEntries(raw.CallRelImm, func(logSize uint32) cairo_components.CallRelImmOpcodeClaim {
		return cairo_components.CallRelImmOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Generic = mapOpcodeClaimEntries(raw.Generic, func(logSize uint32) cairo_components.GenericOpcodeClaim {
		return cairo_components.GenericOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Jnz = mapOpcodeClaimEntries(raw.Jnz, func(logSize uint32) cairo_components.JnzOpcodeClaim {
		return cairo_components.JnzOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.JnzTaken = mapOpcodeClaimEntries(raw.JnzTaken, func(logSize uint32) cairo_components.JnzTakenOpcodeClaim {
		return cairo_components.JnzTakenOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Jump = mapOpcodeClaimEntries(raw.Jump, func(logSize uint32) cairo_components.JumpOpcodeClaim {
		return cairo_components.JumpOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.JumpDoubleDeref = mapOpcodeClaimEntries(raw.JumpDoubleDeref, func(logSize uint32) cairo_components.JumpDoubleDerefOpcodeClaim {
		return cairo_components.JumpDoubleDerefOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.JumpRel = mapOpcodeClaimEntries(raw.JumpRel, func(logSize uint32) cairo_components.JumpRelOpcodeClaim {
		return cairo_components.JumpRelOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.JumpRelImm = mapOpcodeClaimEntries(raw.JumpRelImm, func(logSize uint32) cairo_components.JumpRelImmOpcodeClaim {
		return cairo_components.JumpRelImmOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Mul = mapOpcodeClaimEntries(raw.Mul, func(logSize uint32) cairo_components.MulOpcodeClaim {
		return cairo_components.MulOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.MulSmall = mapOpcodeClaimEntries(raw.MulSmall, func(logSize uint32) cairo_components.MulSmallOpcodeClaim {
		return cairo_components.MulSmallOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Qm31 = mapOpcodeClaimEntries(raw.Qm31, func(logSize uint32) cairo_components.Qm31OpcodeClaim {
		return cairo_components.Qm31OpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})
	claims.Ret = mapOpcodeClaimEntries(raw.Ret, func(logSize uint32) cairo_components.RetOpcodeClaim {
		return cairo_components.RetOpcodeClaim{LogSize: uints.NewU8(uint8(logSize))}
	})

	return claims
}

func buildBlakeContextClaim(raw BlakeContextClaimRawWrapper) BlakeContextClaim {
	if raw.Claim == nil {
		return BlakeContextClaim{}
	}

	var (
		claim   BlakeClaim
		hasData bool
	)

	if entry := raw.Claim.BlakeRound; entry != nil {
		claim.BlakeRound = &cairo_components.BlakeRoundClaim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if entry := raw.Claim.BlakeG; entry != nil {
		claim.BlakeG = &cairo_components.BlakeGClaim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if raw.Claim.BlakeSigma != nil {
		claim.BlakeRoundSigma = &cairo_components.BlakeRoundSigmaClaim{}
		hasData = true
	}
	if entry := raw.Claim.TripleXor32; entry != nil {
		claim.TripleXor32 = &cairo_components.TripleXor32Claim{LogSize: uint32FromUint64(entry.LogSize)}
		hasData = true
	}
	if entry := raw.Claim.VerifyBitwiseXor12; entry != nil {
		claim.VerifyBitwiseXor12 = &SimpleLogSizeClaim{LogSize: uint32FromUint64(entry.LogSize)}
		hasData = true
	}

	if !hasData {
		return BlakeContextClaim{}
	}

	return BlakeContextClaim{Claim: &claim}
}

func buildBuiltinsClaim(raw BuiltinsClaimRaw) BuiltinsClaim {
	var claim BuiltinsClaim
	if raw == nil {
		return claim
	}

	if entry := raw["add_mod_builtin"]; entry != nil && entry.LogSize != nil {
		claim.AddModBuiltin = &cairo_components.AddModBuiltinClaim{
			LogSize:                   uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			AddModBuiltinSegmentStart: uint32FromUint64(ptrUint64(entry.AddModBuiltinSegmentStart)),
		}
	}
	if entry := raw["bitwise_builtin"]; entry != nil && entry.LogSize != nil {
		claim.BitwiseBuiltin = &cairo_components.BitwiseBuiltinClaim{
			LogSize:                    uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			BitwiseBuiltinSegmentStart: uint32FromUint64(ptrUint64(entry.BitwiseBuiltinSegmentStart)),
		}
	}
	if entry := raw["mul_mod_builtin"]; entry != nil && entry.LogSize != nil {
		claim.MulModBuiltin = &cairo_components.MulModBuiltinClaim{
			LogSize:                   uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			MulModBuiltinSegmentStart: uint32FromUint64(ptrUint64(entry.MulModBuiltinSegmentStart)),
		}
	}
	if entry := raw["pedersen_builtin"]; entry != nil && entry.LogSize != nil {
		claim.PedersenBuiltin = &cairo_components.PedersenBuiltinClaim{
			LogSize:                     uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			PedersenBuiltinSegmentStart: uint32FromUint64(ptrUint64(entry.PedersenBuiltinSegmentStart)),
		}
	}
	if entry := raw["poseidon_builtin"]; entry != nil && entry.LogSize != nil {
		claim.PoseidonBuiltin = &cairo_components.PoseidonBuiltinClaim{
			LogSize:                     uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			PoseidonBuiltinSegmentStart: uint32FromUint64(ptrUint64(entry.PoseidonBuiltinSegmentStart)),
		}
	}
	if entry := raw["range_check_96_builtin"]; entry != nil && entry.LogSize != nil {
		claim.RangeCheck96 = &cairo_components.RangeCheck96BuiltinClaim{
			LogSize:                uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			RangeCheckSegmentStart: uint32FromUint64(ptrUint64(entry.RangeCheckBuiltinSegmentStart)),
		}
	}
	if entry := raw["range_check_128_builtin"]; entry != nil && entry.LogSize != nil {
		claim.RangeCheck128 = &cairo_components.RangeCheck128BuiltinClaim{
			LogSize:                uints.NewU8(uint8FromUint64(ptrUint64(entry.LogSize))),
			RangeCheckSegmentStart: uint32FromUint64(ptrUint64(entry.RangeCheckBuiltinSegmentStart)),
		}
	}

	return claim
}

func buildPedersenContextClaim(raw PedersenContextClaimRaw) PedersenContextClaim {
	if raw.Claim == nil {
		return PedersenContextClaim{}
	}

	var (
		claim   PedersenClaim
		hasData bool
	)

	if entry := raw.Claim["partial_ec_mul"]; entry != nil {
		claim.PartialEcMul = &cairo_components.PartialEcMulClaim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if entry := raw.Claim["pedersen_points_table"]; entry != nil {
		claim.PedersenPointsTable = &cairo_components.PedersenPointsTableClaim{}
		hasData = true
	}

	if !hasData {
		return PedersenContextClaim{}
	}

	return PedersenContextClaim{Claim: &claim}
}

func buildPoseidonContextClaim(raw PoseidonContextClaimRaw) PoseidonContextClaim {
	if raw.Claim == nil {
		return PoseidonContextClaim{}
	}

	var (
		claim   PoseidonClaim
		hasData bool
	)

	if entry := raw.Claim.Poseidon3PartialRoundsChain; entry != nil {
		claim.Poseidon3PartialRoundsChain = &cairo_components.Poseidon3PartialRoundsChainClaim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if entry := raw.Claim.PoseidonFullRoundChain; entry != nil {
		claim.PoseidonFullRoundChain = &cairo_components.PoseidonFullRoundChainClaim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if entry := raw.Claim.Cube252; entry != nil {
		claim.Cube252 = &cairo_components.Cube252Claim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}
	if raw.Claim.PoseidonRoundKeys != nil {
		claim.PoseidonRoundKeys = &cairo_components.PoseidonRoundKeysClaim{}
		hasData = true
	}
	if entry := raw.Claim.RangeCheckFelt252Width27; entry != nil {
		claim.RangeCheckFelt252Width27 = &cairo_components.RangeCheckFelt252Width27Claim{LogSize: uints.NewU8(uint8FromUint64(entry.LogSize))}
		hasData = true
	}

	if !hasData {
		return PoseidonContextClaim{}
	}

	return PoseidonContextClaim{Claim: &claim}
}

func buildMemoryIDToValueClaim(raw MemoryIDToValueClaimRaw) MemoryIDToValueClaim {
	var claim MemoryIDToValueClaim

	if len(raw.BigLogSizes) > 0 {
		claim.Big = make([]cairo_components.MemoryIdToBigBigClaim, 0, len(raw.BigLogSizes))
		for idx, entry := range raw.BigLogSizes {
			claim.Big = append(claim.Big, cairo_components.MemoryIdToBigBigClaim{
				LogSize: uints.NewU8(uint8FromUint64(entry)),
				Offset:  uint32(idx),
			})
		}
	}

	if raw.SmallLogSize > 0 {
		claim.Small = &cairo_components.MemoryIdToBigSmallClaim{
			LogSize: uints.NewU8(uint8FromUint64(raw.SmallLogSize)),
		}
	}

	return claim
}

func buildRangeChecksClaim(raw RangeChecksClaimRaw) RangeChecksClaim {
	var claim RangeChecksClaim
	if raw == nil {
		return claim
	}

	claim.RC6 = simpleLogSizeFromEntry(raw["rc_6"])
	claim.RC8 = simpleLogSizeFromEntry(raw["rc_8"])
	claim.RC11 = simpleLogSizeFromEntry(raw["rc_11"])
	claim.RC12 = simpleLogSizeFromEntry(raw["rc_12"])
	claim.RC18 = simpleLogSizeFromEntry(raw["rc_18"])
	claim.RC19 = simpleLogSizeFromEntry(raw["rc_19"])
	claim.RC4_3 = simpleLogSizeFromEntry(raw["rc_4_3"])
	claim.RC4_4 = simpleLogSizeFromEntry(raw["rc_4_4"])
	claim.RC5_4 = simpleLogSizeFromEntry(raw["rc_5_4"])
	claim.RC9_9 = simpleLogSizeFromEntry(raw["rc_9_9"])
	claim.RC7_2_5 = simpleLogSizeFromEntry(raw["rc_7_2_5"])
	claim.RC3_6_6_3 = simpleLogSizeFromEntry(raw["rc_3_6_6_3"])
	claim.RC4_4_4_4 = simpleLogSizeFromEntry(raw["rc_4_4_4_4"])
	claim.RC3_3_3_3_3 = simpleLogSizeFromEntry(raw["rc_3_3_3_3_3"])

	return claim
}

func buildVerifyBitwiseXorClaim(raw VerifyBitwiseXorClaimRaw) *SimpleLogSizeClaim {
	// Treat zero log size as absence.
	if raw.LogSize == 0 {
		return nil
	}
	return &SimpleLogSizeClaim{LogSize: uint32FromUint64(raw.LogSize)}
}

func simpleLogSizeFromEntry(entry *ComponentLogSizeEntry) *SimpleLogSizeClaim {
	if entry == nil {
		return nil
	}
	return &SimpleLogSizeClaim{LogSize: uint32FromUint64(entry.LogSize)}
}

func mapOpcodeClaimEntries[T any](entries []OpcodeLogSizeEntryRaw, wrap func(uint32) T) []T {
	if len(entries) == 0 {
		return nil
	}

	result := make([]T, 0, len(entries))
	for _, entry := range entries {
		result = append(result, wrap(uint32FromUint64(entry.LogSize)))
	}
	return result
}

func ptrUint64(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func uint32FromUint64(value uint64) uint32 {
	if value > math.MaxUint32 {
		panic("log size exceeds uint32 capacity")
	}
	return uint32(value)
}

func uint8FromUint64(value uint64) uint8 {
	if value > math.MaxUint8 {
		panic("log size exceeds uint8 capacity")
	}
	return uint8(value)
}

// ╔══════════════════════════════════╗
// ║     Public Data ClaimBuilding    ║
// ╚══════════════════════════════════╝

// ConstructPublicData builds a PublicData from its raw representation.
func ConstructPublicData(publicDataRaw *PublicDataRaw) PublicData {
	if publicDataRaw == nil {
		return PublicData{}
	}

	publicMemory := constructPublicMemory(publicDataRaw.PublicMemory)
	initialState := constructCasmState(publicDataRaw.InitialState)
	finalState := constructCasmState(publicDataRaw.FinalState)

	return PublicData{
		PublicMemory: publicMemory,
		InitialState: initialState,
		FinalState:   finalState,
	}
}

func constructCasmState(raw RegisterStateRaw) CasmState {
	return CasmState{
		PC: m31.NewM31Unchecked(raw.PC),
		AP: m31.NewM31Unchecked(raw.AP),
		FP: m31.NewM31Unchecked(raw.FP),
	}
}

func constructPublicMemory(raw PublicMemoryRaw) PublicMemory {
	return PublicMemory{
		Program:        convertMemorySection(raw.Program),
		PublicSegments: constructPublicSegmentRanges(raw.PublicSegments),
		Output:         convertMemorySection(raw.Output),
		SafeCall:       convertMemorySection(raw.SafeCall),
	}
}

func convertMemorySection(cells []MemoryCellRaw) []PubMemoryValue {
	if len(cells) == 0 {
		return nil
	}

	section := make([]PubMemoryValue, 0, len(cells))
	for _, cell := range cells {
		section = append(section, PubMemoryValue{
			ID:    m31.NewM31Unchecked(cell.Address),
			Value: SplitFeltWords(*(*[8]uint32)(cell.Value)), // values are necessarily 8 limbs of 32 bits
		})
	}
	return section
}

func constructPublicSegmentRanges(raw map[string]*SegmentRangeRaw) PublicSegmentRanges {
	if raw == nil {
		return PublicSegmentRanges{}
	}

	var ranges PublicSegmentRanges

	ranges.Output = constructSegmentRange(raw["output"])

	if segment := raw["pedersen"]; segment != nil {
		ranges.Pedersen = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["range_check_128"]; segment != nil {
		ranges.RangeCheck128 = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["ecdsa"]; segment != nil {
		ranges.Ecdsa = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["bitwise"]; segment != nil {
		ranges.Bitwise = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["ec_op"]; segment != nil {
		ranges.EcOp = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["keccak"]; segment != nil {
		ranges.Keccak = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["poseidon"]; segment != nil {
		ranges.Poseidon = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["range_check_96"]; segment != nil {
		ranges.RangeCheck96 = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["add_mod"]; segment != nil {
		ranges.AddMod = ptrSegmentRange(constructSegmentRange(segment))
	}
	if segment := raw["mul_mod"]; segment != nil {
		ranges.MulMod = ptrSegmentRange(constructSegmentRange(segment))
	}

	return ranges
}

func constructSegmentRange(raw *SegmentRangeRaw) SegmentRange {
	if raw == nil {
		return SegmentRange{}
	}

	return SegmentRange{
		StartPtr: constructSegmentPointer(raw.StartPtr),
		StopPtr:  constructSegmentPointer(raw.StopPtr),
	}
}

func constructSegmentPointer(raw *SegmentPointerRaw) SegmentPointer {
	if raw == nil {
		return SegmentPointer{}
	}
	value := [8]uint32{raw.Value, 0, 0, 0, 0, 0, 0, 0}
	return SegmentPointer{
		ID:    m31.NewM31Unchecked(raw.ID),
		Value: SplitFeltWords(value),
	}
}

// Creates a copy from which we can take the address
func ptrSegmentRange(segment SegmentRange) *SegmentRange {
	seg := segment
	return &seg
}

// ╔══════════════════════════════════╗
// ║    Interaction Claim Building    ║
// ╚══════════════════════════════════╝

// BuildInteractionClaim builds a CairoInteractionClaim from a InteractionClaimRaw
func BuildInteractionClaim(interactionClaimRaw *InteractionClaimRaw) CairoInteractionClaim {
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
	claim.Blake = mapOpcodeEntries(raw["blake"], func(sum m31.QM31) cairo_components.BlakeCompressOpcodeInteractionClaim {
		return cairo_components.BlakeCompressOpcodeInteractionClaim{ClaimedSum: sum}
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
// ║        StarkProof Building       ║
// ╚══════════════════════════════════╝

// BuildStarkProof builds a StarkProof from its raw representation.
func BuildStarkProof(starkProofRaw *StarkProofRaw) StarkProof {
	if starkProofRaw == nil {
		return StarkProof{}
	}

	return StarkProof{
		SampledValues: buildSampledValues(starkProofRaw.SampledValues),
		QueriedValues: buildQueriedValues(starkProofRaw.QueriedValues),
		Decommitments: buildDecommitments(starkProofRaw.Decommitments),
	}
}

func buildSampledValues(raw SampledValuesRaw) [][][]m31.QM31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][][]m31.QM31, len(raw))
	for domainIdx, columns := range raw {
		if len(columns) == 0 {
			continue
		}

		domainValues := make([][]m31.QM31, len(columns))
		for columnIdx, evaluations := range columns {
			if len(evaluations) == 0 {
				continue
			}

			columnValues := make([]m31.QM31, 0, len(evaluations))
			for _, entry := range evaluations {
				if value, ok := qm31FromUint64Pairs(entry); ok {
					columnValues = append(columnValues, value)
				}
			}
			domainValues[columnIdx] = columnValues
		}
		result[domainIdx] = domainValues
	}

	return result
}

func buildQueriedValues(raw [][]uint64) [][]m31.M31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][]m31.M31, len(raw))
	for groupIdx, group := range raw {
		if len(group) == 0 {
			continue
		}

		result[groupIdx] = convertUintSliceToM31(group)
	}

	return result
}

func buildDecommitments(raw []MerkleDecommitmentRaw) []MerkleDecommitment {
	if len(raw) == 0 {
		return nil
	}

	result := make([]MerkleDecommitment, len(raw))
	for i, entry := range raw {
		result[i] = MerkleDecommitment{
			HashWitness:   buildHashWitness(entry.HashWitness),
			ColumnWitness: convertUintSliceToM31(entry.ColumnWitness),
		}
	}

	return result
}

// ╔══════════════════════════════════╗
// ║         Helper functions         ║
// ╚══════════════════════════════════╝

// SplitFeltWords converts eight 32-bit limbs into NM31InFelt252 M31 limbs with N_BITS_PER_FELT bits each.
func SplitFeltWords(words [8]uint32) Felt252Value {
	// Build the big integer from the limbs
	acc := big.NewInt(0)
	tmp := new(big.Int)
	for i := len(words) - 1; i >= 0; i-- {
		acc.Lsh(acc, 32)
		tmp.SetUint64(uint64(words[i]))
		acc.Or(acc, tmp)
	}

	mask := new(big.Int).Lsh(big.NewInt(1), BitsPerFelt252)
	mask.Sub(mask, big.NewInt(1))

	// Split the big integer into NM31InFelt252 M31 limbs
	var result Felt252Value
	for i := 0; i < NM31InFelt252; i++ {
		tmp.And(acc, mask)
		result[i] = m31.NewM31Unchecked(tmp.Uint64())
		acc.Rsh(acc, BitsPerFelt252)
	}

	return result
}

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

func buildHashWitness(raw [][]uint8) [][32]uints.U8 {
	if len(raw) == 0 {
		return nil
	}

	hashes := make([][32]uints.U8, len(raw))
	for i, bytes := range raw {
		var hash [32]uints.U8
		for j := 0; j < len(hash) && j < len(bytes); j++ {
			hash[j] = uints.NewU8(bytes[j])
		}
		hashes[i] = hash
	}

	return hashes
}

func convertUintSliceToM31(values []uint64) []m31.M31 {
	if len(values) == 0 {
		return nil
	}

	result := make([]m31.M31, len(values))
	for i, v := range values {
		result[i] = m31.NewM31Unchecked(v)
	}
	return result
}

func ProofFixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "test_data", name)
}

const (
	HdpProofFixture                 = "hdp_proof.json"
	AllComponentsProofFixture       = "all_components_proof.json"
	AllComponentsStaticProofFixture = "all_components_proof_static.json"
)
