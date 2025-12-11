package variables

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
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

// ReadCircuitShape loads a circuit shape file from disk.
func ReadCircuitShape(path string) (*CircuitShapeRaw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	return ReadCircuitShapeFromReader(file)
}

// ReadCircuitShapeFromReader decodes a circuit shape from the supplied reader.
func ReadCircuitShapeFromReader(r io.Reader) (*CircuitShapeRaw, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var shape CircuitShapeRaw
	if err := json.Unmarshal(data, &shape); err != nil {
		return nil, err
	}

	return &shape, nil
}

// BuildProof builds a Proof (used in circuits) from a ProofRaw (from json)
func BuildProof(proofRaw ProofRaw) Proof {
	var proof Proof

	claim := BuildClaim(&proofRaw.Claim)
	proof.Claim = claim
	proof.InteractionPow = uints.NewU64(proofRaw.InteractionPow)
	proof.InteractionClaim = BuildInteractionClaim(&proofRaw.InteractionClaim)
	proof.StarkProof = BuildStarkProof(&proofRaw.StarkProof)

	return proof
}

// ╔══════════════════════════════════╗
// ║       Circuit Data Building      ║
// ╚══════════════════════════════════╝

// BuildCircuitData builds CircuitData from the raw JSON shape description.
func BuildCircuitData(shapeRaw *CircuitShapeRaw) CircuitData {
	if shapeRaw == nil {
		return CircuitData{}
	}
	return buildCircuitDataFromShape(*shapeRaw)
}

func buildCircuitDataFromShape(shape CircuitShapeRaw) CircuitData {
	if len(shape.ColumnLogSizes) != cairo_components.N_TREES {
		panic(fmt.Sprintf("expected %d column trees, got %d", cairo_components.N_TREES, len(shape.ColumnLogSizes)))
	}

	columnLogSizes := make([][]int, len(shape.ColumnLogSizes))
	for i, tree := range shape.ColumnLogSizes {
		columnLogSizes[i] = append([]int(nil), tree...)
	}

	var componentConfig ComponentConfig
	if len(shape.ComponentConfig) != len(componentConfig) {
		panic(fmt.Sprintf("expected %d component config entries, got %d", len(componentConfig), len(shape.ComponentConfig)))
	}
	copy(componentConfig[:], shape.ComponentConfig)

	var preprocessedConfig PreprocessedConfig
	if len(shape.PreprocessedConfig) != len(preprocessedConfig) {
		panic(fmt.Sprintf("expected %d preprocessed config entries, got %d", len(preprocessedConfig), len(shape.PreprocessedConfig)))
	}
	copy(preprocessedConfig[:], shape.PreprocessedConfig)

	dedupedQueriesShape := append([]int(nil), shape.DedupedQueriesShape...)

	maxObservedLogSize := 0
	maxTraceLogSize := 0
	for treeIdx, tree := range columnLogSizes {
		for _, logSize := range tree {
			if logSize > maxObservedLogSize {
				maxObservedLogSize = logSize
			}
			if (treeIdx == cairo_components.MAIN_IDX || treeIdx == cairo_components.INTERACTION_IDX) && logSize > maxTraceLogSize {
				maxTraceLogSize = logSize
			}
		}
	}

	bucketLen := len(dedupedQueriesShape)
	if bucketLen == 0 || bucketLen <= maxObservedLogSize {
		bucketLen = maxObservedLogSize + 1
	}

	nColumnsPerLogSize := make([][]int, cairo_components.N_TREES)
	for treeIdx := range nColumnsPerLogSize {
		nColumnsPerLogSize[treeIdx] = make([]int, bucketLen)
		for _, logSize := range columnLogSizes[treeIdx] {
			if logSize < 0 {
				panic("log size cannot be negative")
			}
			if logSize >= len(nColumnsPerLogSize[treeIdx]) {
				extended := make([]int, logSize+1)
				copy(extended, nColumnsPerLogSize[treeIdx])
				nColumnsPerLogSize[treeIdx] = extended
			}
			nColumnsPerLogSize[treeIdx][logSize]++
		}
	}

	uniqueLogSizes := make(map[int]struct{})
	for _, tree := range columnLogSizes {
		for _, logSize := range tree {
			uniqueLogSizes[logSize] = struct{}{}
		}
	}
	columnBounds := make([]int, 0, len(uniqueLogSizes))
	for logSize := range uniqueLogSizes {
		columnBounds = append(columnBounds, logSize+1)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(columnBounds)))

	return CircuitData{
		ComponentConfig:     componentConfig,
		PreprocessedConfig:  preprocessedConfig,
		ColumnLogSizes:      columnLogSizes,
		ColumnBounds:        columnBounds,
		NColumnsPerLogSize:  nColumnsPerLogSize,
		BoundsLength:        len(uniqueLogSizes),
		DedupedQueriesShape: dedupedQueriesShape,
		MaxLogSize:          uint8(maxTraceLogSize),
	}
}

// ╔══════════════════════════════════╗
// ║         Claim Building           ║
// ╚══════════════════════════════════╝

// BuildClaim builds a CairoClaim from a ClaimRaw
func BuildClaim(claimRaw *ClaimRaw) CairoClaim {
	if claimRaw == nil {
		return CairoClaim{}
	}

	claim := CairoClaim{}.Default()

	// Build public data
	claim.PublicData = BuildPublicData(&claimRaw.PublicData)

	// Build opcodes
	if len(claimRaw.Opcodes.Add) > 0 {
		claim.Add = cairo_components.AddOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Add[0].LogSize)}
	}
	if len(claimRaw.Opcodes.AddSmall) > 0 {
		claim.AddSmall = cairo_components.AddSmallOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.AddSmall[0].LogSize)}
	}
	if len(claimRaw.Opcodes.AddAp) > 0 {
		claim.AddAp = cairo_components.AddApOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.AddAp[0].LogSize)}
	}
	if len(claimRaw.Opcodes.AssertEq) > 0 {
		claim.AssertEq = cairo_components.AssertEqOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.AssertEq[0].LogSize)}
	}
	if len(claimRaw.Opcodes.AssertEqImm) > 0 {
		claim.AssertEqImm = cairo_components.AssertEqImmOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.AssertEqImm[0].LogSize)}
	}
	if len(claimRaw.Opcodes.AssertEqDoubleDeref) > 0 {
		claim.AssertEqDoubleDeref = cairo_components.AssertEqDoubleDerefOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.AssertEqDoubleDeref[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Blake) > 0 {
		claim.Blake = cairo_components.BlakeCompressOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Blake[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Call) > 0 {
		claim.Call = cairo_components.CallOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Call[0].LogSize)}
	}
	if len(claimRaw.Opcodes.CallRelImm) > 0 {
		claim.CallRelImm = cairo_components.CallRelImmOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.CallRelImm[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Generic) > 0 {
		claim.Generic = cairo_components.GenericOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Generic[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Jnz) > 0 {
		claim.Jnz = cairo_components.JnzOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Jnz[0].LogSize)}
	}
	if len(claimRaw.Opcodes.JnzTaken) > 0 {
		claim.JnzTaken = cairo_components.JnzTakenOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.JnzTaken[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Jump) > 0 {
		claim.Jump = cairo_components.JumpOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Jump[0].LogSize)}
	}
	if len(claimRaw.Opcodes.JumpDoubleDeref) > 0 {
		claim.JumpDoubleDeref = cairo_components.JumpDoubleDerefOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.JumpDoubleDeref[0].LogSize)}
	}
	if len(claimRaw.Opcodes.JumpRel) > 0 {
		claim.JumpRel = cairo_components.JumpRelOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.JumpRel[0].LogSize)}
	}
	if len(claimRaw.Opcodes.JumpRelImm) > 0 {
		claim.JumpRelImm = cairo_components.JumpRelImmOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.JumpRelImm[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Mul) > 0 {
		claim.Mul = cairo_components.MulOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Mul[0].LogSize)}
	}
	if len(claimRaw.Opcodes.MulSmall) > 0 {
		claim.MulSmall = cairo_components.MulSmallOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.MulSmall[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Qm31) > 0 {
		claim.Qm31 = cairo_components.Qm31OpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Qm31[0].LogSize)}
	}
	if len(claimRaw.Opcodes.Ret) > 0 {
		claim.Ret = cairo_components.RetOpcodeClaim{LogSize: frontend.Variable(claimRaw.Opcodes.Ret[0].LogSize)}
	}

	// Build verify instruction
	claim.VerifyInstruction = cairo_components.VerifyInstructionClaim{LogSize: frontend.Variable(claimRaw.VerifyInstruction.LogSize)}

	// Build Blake context
	if claimRaw.BlakeContext.Claim != nil {
		claim.BlakeRound = cairo_components.BlakeRoundClaim{LogSize: frontend.Variable(claimRaw.BlakeContext.Claim.BlakeRound.LogSize)}
		claim.BlakeG = cairo_components.BlakeGClaim{LogSize: frontend.Variable(claimRaw.BlakeContext.Claim.BlakeG.LogSize)}
		claim.BlakeRoundSigma = cairo_components.BlakeRoundSigmaClaim{LogSize: cairo_components.BlakeRoundSigmaLogSize}
		claim.TripleXor32 = cairo_components.TripleXor32Claim{LogSize: frontend.Variable(claimRaw.BlakeContext.Claim.TripleXor32.LogSize)}
		claim.VerifyBitwiseXor12 = cairo_components.VerifyBitwiseXor12Claim{LogSize: cairo_components.VerifyBitwiseXor12LogSize}
	}

	// Build builtins
	if claimRaw.Builtins["add_mod_builtin"] != nil {
		claim.AddModBuiltin = cairo_components.AddModBuiltinClaim{
			LogSize:                   frontend.Variable(claimRaw.Builtins["add_mod_builtin"].LogSize),
			AddModBuiltinSegmentStart: frontend.Variable(claimRaw.Builtins["add_mod_builtin"].AddModBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["bitwise_builtin"] != nil {
		claim.BitwiseBuiltin = cairo_components.BitwiseBuiltinClaim{
			LogSize:                    frontend.Variable(claimRaw.Builtins["bitwise_builtin"].LogSize),
			BitwiseBuiltinSegmentStart: frontend.Variable(claimRaw.Builtins["bitwise_builtin"].BitwiseBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["mul_mod_builtin"] != nil {
		claim.MulModBuiltin = cairo_components.MulModBuiltinClaim{
			LogSize:                   frontend.Variable(claimRaw.Builtins["mul_mod_builtin"].LogSize),
			MulModBuiltinSegmentStart: frontend.Variable(claimRaw.Builtins["mul_mod_builtin"].MulModBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["pedersen_builtin"] != nil {
		claim.PedersenBuiltin = cairo_components.PedersenBuiltinClaim{
			LogSize:                     frontend.Variable(claimRaw.Builtins["pedersen_builtin"].LogSize),
			PedersenBuiltinSegmentStart: frontend.Variable(claimRaw.Builtins["pedersen_builtin"].PedersenBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["poseidon_builtin"] != nil {
		claim.PoseidonBuiltin = cairo_components.PoseidonBuiltinClaim{
			LogSize:                     frontend.Variable(claimRaw.Builtins["poseidon_builtin"].LogSize),
			PoseidonBuiltinSegmentStart: frontend.Variable(claimRaw.Builtins["poseidon_builtin"].PoseidonBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["range_check_96_builtin"] != nil {
		claim.RangeCheck96 = cairo_components.RangeCheck96BuiltinClaim{
			LogSize:                frontend.Variable(claimRaw.Builtins["range_check_96_builtin"].LogSize),
			RangeCheckSegmentStart: frontend.Variable(claimRaw.Builtins["range_check_96_builtin"].RangeCheckBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["range_check_128_builtin"] != nil {
		claim.RangeCheck128 = cairo_components.RangeCheck128BuiltinClaim{
			LogSize:                frontend.Variable(claimRaw.Builtins["range_check_128_builtin"].LogSize),
			RangeCheckSegmentStart: frontend.Variable(claimRaw.Builtins["range_check_128_builtin"].RangeCheckBuiltinSegmentStart),
		}
	}

	// Build pedersen context
	if claimRaw.PedersenContext.Claim != nil {
		claim.PartialEcMul = cairo_components.PartialEcMulClaim{LogSize: frontend.Variable(claimRaw.PedersenContext.Claim["partial_ec_mul"].LogSize)}
		claim.PedersenPointsTable = cairo_components.PedersenPointsTableClaim{LogSize: cairo_components.PedersenPointsTableLogSize}
	}

	// Build poseidon context
	if claimRaw.PoseidonContext.Claim != nil {
		claim.Poseidon3PartialRoundsChain = cairo_components.Poseidon3PartialRoundsChainClaim{LogSize: frontend.Variable(claimRaw.PoseidonContext.Claim.Poseidon3PartialRoundsChain.LogSize)}
		claim.PoseidonFullRoundChain = cairo_components.PoseidonFullRoundChainClaim{LogSize: frontend.Variable(claimRaw.PoseidonContext.Claim.PoseidonFullRoundChain.LogSize)}
		claim.Cube252 = cairo_components.Cube252Claim{LogSize: frontend.Variable(claimRaw.PoseidonContext.Claim.Cube252.LogSize)}
		claim.PoseidonRoundKeys = cairo_components.PoseidonRoundKeysClaim{LogSize: cairo_components.PoseidonRoundKeysLogSize}
		claim.RangeCheckFelt252Width27 = cairo_components.RangeCheckFelt252Width27Claim{LogSize: frontend.Variable(claimRaw.PoseidonContext.Claim.RangeCheckFelt252Width27.LogSize)}
	}

	// Build memory address to id component
	claim.MemoryAddressToID = cairo_components.MemoryAddressToIDClaim{LogSize: frontend.Variable(claimRaw.MemoryAddressToId.LogSize)}

	// Build ID to Big Big memory components
	// TODO: Handle multiple id to big tables
	claim.MemoryIDToBigBig = cairo_components.MemoryIdToBigBigClaim{
		LogSize: frontend.Variable(claimRaw.MemoryIDToValue.BigLogSizes[0]),
		Offset:  uint32(0),
	}

	// Build ID to Big Small memory components
	claim.MemoryIDToBigSmall = cairo_components.MemoryIdToBigSmallClaim{
		LogSize: frontend.Variable(claimRaw.MemoryIDToValue.SmallLogSize),
	}

	// Build range checks
	claim.RC6 = cairo_components.RangeCheck6Claim{LogSize: cairo_components.RangeCheck6LogSize}
	claim.RC8 = cairo_components.RangeCheck8Claim{LogSize: cairo_components.RangeCheck8LogSize}
	claim.RC11 = cairo_components.RangeCheck11Claim{LogSize: cairo_components.RangeCheck11LogSize}
	claim.RC12 = cairo_components.RangeCheck12Claim{LogSize: cairo_components.RangeCheck12LogSize}
	claim.RC18 = cairo_components.RangeCheck18Claim{LogSize: cairo_components.RangeCheck18LogSize}
	claim.RC19 = cairo_components.RangeCheck19Claim{LogSize: cairo_components.RangeCheck19LogSize}
	claim.RC43 = cairo_components.RangeCheck43Claim{LogSize: cairo_components.RangeCheck43LogSize}
	claim.RC44 = cairo_components.RangeCheck44Claim{LogSize: cairo_components.RangeCheck44LogSize}
	claim.RC54 = cairo_components.RangeCheck54Claim{LogSize: cairo_components.RangeCheck54LogSize}
	claim.RC99 = cairo_components.RangeCheck99Claim{LogSize: cairo_components.RangeCheck99LogSize}
	claim.RC725 = cairo_components.RangeCheck725Claim{LogSize: cairo_components.RangeCheck725LogSize}
	claim.RC3663 = cairo_components.RangeCheck3663Claim{LogSize: cairo_components.RangeCheck3663LogSize}
	claim.RC4444 = cairo_components.RangeCheck4444Claim{LogSize: cairo_components.RangeCheck4444LogSize}
	claim.RC33333 = cairo_components.RangeCheck33333Claim{LogSize: cairo_components.RangeCheck33333LogSize}

	// Build bitwise XOR
	claim.VerifyBitwiseXor4 = cairo_components.VerifyBitwiseXor4Claim{LogSize: cairo_components.VerifyBitwiseXor4LogSize}
	claim.VerifyBitwiseXor7 = cairo_components.VerifyBitwiseXor7Claim{LogSize: cairo_components.VerifyBitwiseXor7LogSize}
	claim.VerifyBitwiseXor8 = cairo_components.VerifyBitwiseXor8Claim{LogSize: cairo_components.VerifyBitwiseXor8LogSize}
	claim.VerifyBitwiseXor9 = cairo_components.VerifyBitwiseXor9Claim{LogSize: cairo_components.VerifyBitwiseXor9LogSize}

	return claim
}

// ╔══════════════════════════════════╗
// ║     Public Data ClaimBuilding    ║
// ╚══════════════════════════════════╝

// BuildPublicData builds a PublicData from its raw representation.
func BuildPublicData(publicDataRaw *PublicDataRaw) PublicData {
	if publicDataRaw == nil {
		return PublicData{}
	}

	publicMemory := buildPublicMemory(publicDataRaw.PublicMemory)
	initialState := buildCasmState(publicDataRaw.InitialState)
	finalState := buildCasmState(publicDataRaw.FinalState)

	return PublicData{
		PublicMemory: publicMemory,
		InitialState: initialState,
		FinalState:   finalState,
	}
}

func buildCasmState(raw RegisterStateRaw) CasmState {
	return CasmState{
		PC: m31.NewM31Unchecked(raw.PC),
		AP: m31.NewM31Unchecked(raw.AP),
		FP: m31.NewM31Unchecked(raw.FP),
	}
}

func buildPublicMemory(raw PublicMemoryRaw) PublicMemory {
	return PublicMemory{
		Program:        convertMemorySection(raw.Program),
		PublicSegments: buildPublicSegmentRanges(raw.PublicSegments),
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

func buildPublicSegmentRanges(raw map[string]*SegmentRangeRaw) PublicSegmentRanges {
	if raw == nil {
		return PublicSegmentRanges{}
	}

	var ranges PublicSegmentRanges

	ranges.Output = buildSegmentRange(raw["output"])

	if segment := raw["pedersen"]; segment != nil {
		ranges.Pedersen = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["range_check_128"]; segment != nil {
		ranges.RangeCheck128 = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["ecdsa"]; segment != nil {
		ranges.Ecdsa = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["bitwise"]; segment != nil {
		ranges.Bitwise = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["ec_op"]; segment != nil {
		ranges.EcOp = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["keccak"]; segment != nil {
		ranges.Keccak = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["poseidon"]; segment != nil {
		ranges.Poseidon = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["range_check_96"]; segment != nil {
		ranges.RangeCheck96 = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["add_mod"]; segment != nil {
		ranges.AddMod = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["mul_mod"]; segment != nil {
		ranges.MulMod = ptrSegmentRange(buildSegmentRange(segment))
	}

	return ranges
}

func buildSegmentRange(raw *SegmentRangeRaw) SegmentRange {
	if raw == nil {
		return SegmentRange{}
	}

	return SegmentRange{
		StartPtr: buildSegmentPointer(raw.StartPtr),
		StopPtr:  buildSegmentPointer(raw.StopPtr),
	}
}

func buildSegmentPointer(raw *SegmentPointerRaw) SegmentPointer {
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

	interactionClaim := CairoInteractionClaim{}.Default()

	// Opcode interaction claim
	if len(interactionClaimRaw.Opcodes["add"]) > 0 {
		interactionClaim.Add = cairo_components.AddOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["add"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["add_small"]) > 0 {
		interactionClaim.AddSmall = cairo_components.AddSmallOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["add_small"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["add_ap"]) > 0 {
		interactionClaim.AddAp = cairo_components.AddApOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["add_ap"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["assert_eq"]) > 0 {
		interactionClaim.AssertEq = cairo_components.AssertEqOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["assert_eq"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["assert_eq_imm"]) > 0 {
		interactionClaim.AssertEqImm = cairo_components.AssertEqImmOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["assert_eq_imm"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["assert_eq_double_deref"]) > 0 {
		interactionClaim.AssertEqDoubleDeref = cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["assert_eq_double_deref"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["blake"]) > 0 {
		interactionClaim.Blake = cairo_components.BlakeCompressOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["blake"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["call"]) > 0 {
		interactionClaim.Call = cairo_components.CallOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["call"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["call_rel_imm"]) > 0 {
		interactionClaim.CallRelImm = cairo_components.CallRelImmOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["call_rel_imm"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["generic"]) > 0 {
		interactionClaim.Generic = cairo_components.GenericOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["generic"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jnz"]) > 0 {
		interactionClaim.Jnz = cairo_components.JnzOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jnz"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jnz_taken"]) > 0 {
		interactionClaim.JnzTaken = cairo_components.JnzTakenOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jnz_taken"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jump"]) > 0 {
		interactionClaim.Jump = cairo_components.JumpOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jump"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jump_double_deref"]) > 0 {
		interactionClaim.JumpDoubleDeref = cairo_components.JumpDoubleDerefOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jump_double_deref"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jump_rel"]) > 0 {
		interactionClaim.JumpRel = cairo_components.JumpRelOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jump_rel"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["jump_rel_imm"]) > 0 {
		interactionClaim.JumpRelImm = cairo_components.JumpRelImmOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["jump_rel_imm"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["mul"]) > 0 {
		interactionClaim.Mul = cairo_components.MulOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["mul"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["mul_small"]) > 0 {
		interactionClaim.MulSmall = cairo_components.MulSmallOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["mul_small"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["qm31"]) > 0 {
		interactionClaim.Qm31 = cairo_components.Qm31OpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["qm31"][0].ClaimedSum)}
	}
	if len(interactionClaimRaw.Opcodes["ret"]) > 0 {
		interactionClaim.Ret = cairo_components.RetOpcodeInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Opcodes["ret"][0].ClaimedSum)}
	}

	// Verify instruction interaction claim
	interactionClaim.VerifyInstruction = cairo_components.VerifyInstructionInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.VerifyInstruction.ClaimedSum)}

	// Blake context interaction claim
	if interactionClaimRaw.BlakeContext.Claim != nil {
		interactionClaim.BlakeG = cairo_components.BlakeGInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.BlakeContext.Claim.BlakeG.ClaimedSum)}
		interactionClaim.BlakeRound = cairo_components.BlakeRoundInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.BlakeContext.Claim.BlakeRound.ClaimedSum)}
		interactionClaim.BlakeRoundSigma = cairo_components.BlakeRoundSigmaInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.BlakeContext.Claim.BlakeSigma.ClaimedSum)}
		interactionClaim.TripleXor32 = cairo_components.TripleXor32InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.BlakeContext.Claim.TripleXor32.ClaimedSum)}
		interactionClaim.VerifyBitwiseXor12 = cairo_components.VerifyBitwiseXor12InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.BlakeContext.Claim.VerifyBitwiseXor12.ClaimedSum)}
	}

	// Builtins interaction claim
	if interactionClaimRaw.Builtins["add_mod_builtin"] != nil {
		interactionClaim.AddModBuiltin = cairo_components.AddModBuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["add_mod_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["bitwise_builtin"] != nil {
		interactionClaim.BitwiseBuiltin = cairo_components.BitwiseBuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["bitwise_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["mul_mod_builtin"] != nil {
		interactionClaim.MulModBuiltin = cairo_components.MulModBuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["mul_mod_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["pedersen_builtin"] != nil {
		interactionClaim.PedersenBuiltin = cairo_components.PedersenBuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["pedersen_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["poseidon_builtin"] != nil {
		interactionClaim.PoseidonBuiltin = cairo_components.PoseidonBuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["poseidon_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["range_check_96_builtin"] != nil {
		interactionClaim.RangeCheck96 = cairo_components.RangeCheck96BuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["range_check_96_builtin"].ClaimedSum)}
	}
	if interactionClaimRaw.Builtins["range_check_128_builtin"] != nil {
		interactionClaim.RangeCheck128 = cairo_components.RangeCheck128BuiltinInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.Builtins["range_check_128_builtin"].ClaimedSum)}
	}

	// Pedersen context interaction claim
	if pedersenCtx := interactionClaimRaw.PedersenContext.Claim; pedersenCtx != nil {
		if partialEcMulClaim := pedersenCtx["partial_ec_mul"]; partialEcMulClaim != nil {
			interactionClaim.PartialEcMul = cairo_components.PartialEcMulInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(partialEcMulClaim.ClaimedSum)}
		}
		if pedersenTableClaim := pedersenCtx["pedersen_points_table"]; pedersenTableClaim != nil {
			interactionClaim.PedersenPointsTable = cairo_components.PedersenPointsTableInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(pedersenTableClaim.ClaimedSum)}
		}
	}

	// Poseidon context interaction claim
	if poseidonCtx := interactionClaimRaw.PoseidonContext.Claim; poseidonCtx != nil {
		if poseidonCtx.Poseidon3PartialRoundsChain != nil {
			interactionClaim.Poseidon3PartialRoundsChain = cairo_components.Poseidon3PartialRoundsChainInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(poseidonCtx.Poseidon3PartialRoundsChain.ClaimedSum)}
		}
		if poseidonCtx.PoseidonFullRoundChain != nil {
			interactionClaim.PoseidonFullRoundChain = cairo_components.PoseidonFullRoundChainInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(poseidonCtx.PoseidonFullRoundChain.ClaimedSum)}
		}
		if poseidonCtx.Cube252 != nil {
			interactionClaim.Cube252 = cairo_components.Cube252InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(poseidonCtx.Cube252.ClaimedSum)}
		}
		if poseidonCtx.PoseidonRoundKeys != nil {
			interactionClaim.PoseidonRoundKeys = cairo_components.PoseidonRoundKeysInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(poseidonCtx.PoseidonRoundKeys.ClaimedSum)}
		}
		if poseidonCtx.RangeCheckFelt252Width27 != nil {
			interactionClaim.RangeCheckFelt252Width27 = cairo_components.RangeCheckFelt252Width27InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(poseidonCtx.RangeCheckFelt252Width27.ClaimedSum)}
		}
	}

	// Memory address to id interaction claim
	interactionClaim.MemoryAddressToID = cairo_components.MemoryAddressToIDInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryAddressToId.ClaimedSum)}

	// Memory ID to value interaction claim
	// TODO: handle multiple big claims
	interactionClaim.MemoryIDToBigBig = cairo_components.MemoryIdToBigBigInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryIDToValue.BigClaimedSums[0])}
	interactionClaim.MemoryIDToBigSmall = cairo_components.MemoryIdToBigSmallInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryIDToValue.SmallClaimedSum)}

	// Range checks interaction claim
	interactionClaim.RC6 = cairo_components.RangeCheck6InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_6"].ClaimedSum)}
	interactionClaim.RC8 = cairo_components.RangeCheck8InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_8"].ClaimedSum)}
	interactionClaim.RC11 = cairo_components.RangeCheck11InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_11"].ClaimedSum)}
	interactionClaim.RC12 = cairo_components.RangeCheck12InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_12"].ClaimedSum)}
	interactionClaim.RC18 = cairo_components.RangeCheck18InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_18"].ClaimedSum)}
	interactionClaim.RC19 = cairo_components.RangeCheck19InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_19"].ClaimedSum)}
	interactionClaim.RC43 = cairo_components.RangeCheck43InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_4_3"].ClaimedSum)}
	interactionClaim.RC44 = cairo_components.RangeCheck44InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_4_4"].ClaimedSum)}
	interactionClaim.RC54 = cairo_components.RangeCheck54InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_5_4"].ClaimedSum)}
	interactionClaim.RC99 = cairo_components.RangeCheck99InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_9_9"].ClaimedSum)}
	interactionClaim.RC725 = cairo_components.RangeCheck725InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_7_2_5"].ClaimedSum)}
	interactionClaim.RC3663 = cairo_components.RangeCheck3663InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_3_6_6_3"].ClaimedSum)}
	interactionClaim.RC4444 = cairo_components.RangeCheck4444InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_4_4_4_4"].ClaimedSum)}
	interactionClaim.RC33333 = cairo_components.RangeCheck33333InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.RangeChecks["rc_3_3_3_3_3"].ClaimedSum)}

	// Verify Bitwise Xor interaction claims
	interactionClaim.VerifyBitwiseXor4 = cairo_components.VerifyBitwiseXor4InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.VerifyBitwiseXor4.ClaimedSum)}
	interactionClaim.VerifyBitwiseXor7 = cairo_components.VerifyBitwiseXor7InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.VerifyBitwiseXor7.ClaimedSum)}
	interactionClaim.VerifyBitwiseXor8 = cairo_components.VerifyBitwiseXor8InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.VerifyBitwiseXor8.ClaimedSum)}
	interactionClaim.VerifyBitwiseXor9 = cairo_components.VerifyBitwiseXor9InteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.VerifyBitwiseXor9.ClaimedSum)}

	return interactionClaim
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
		Commitments:   buildCommitments(starkProofRaw.Commitments),
		SampledValues: buildSampledValues(starkProofRaw.SampledValues),
		QueriedValues: buildQueriedValues(starkProofRaw.QueriedValues),
		Decommitments: buildDecommitments(starkProofRaw.Decommitments),
		FriProof:      buildFriProof(starkProofRaw.FriProof),
		ProofOfWork:   uints.NewU64(starkProofRaw.ProofOfWork),
	}
}

func buildCommitments(raw [][]uint8) [][32]uints.U8 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][32]uints.U8, len(raw))
	for i, entry := range raw {
		if len(entry) != 32 {
			panic("commitment root must be 32 bytes")
		}
		var root [32]uints.U8
		for j, b := range entry {
			root[j] = uints.NewU8(b)
		}
		result[i] = root
	}

	return result
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
				columnValues = append(columnValues, m31.NewQM31FromArrays(entry))
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

func buildFriProof(raw FriProofRaw) FriProof {
	return FriProof{
		FirstLayerProof:  buildFirstLayerProof(raw.FirstLayerProof),
		InnerLayerProofs: buildInnerLayerProofs(raw.InnerLayerProofs),
		LastLayerPoly:    buildLastLayerPoly(raw.LastLayerPoly),
	}
}

func buildFirstLayerProof(raw FriLayerProofRaw) FriLayerProof {
	firstLayerProof := buildInnerLayerProof(raw)
	return firstLayerProof
}

func buildInnerLayerProofs(raw []FriLayerProofRaw) []FriLayerProof {
	result := make([]FriLayerProof, len(raw))
	for i, entry := range raw {
		result[i] = buildInnerLayerProof(entry)
	}
	return result
}

func buildInnerLayerProof(raw FriLayerProofRaw) FriLayerProof {
	friWitness := make([]m31.QM31, len(raw.FriWitness))
	for i, entry := range raw.FriWitness {
		friWitness[i] = m31.NewQM31FromArrays(entry)
	}

	decommitment := buildDecommitments([]MerkleDecommitmentRaw{raw.Decommitment})[0]

	commitment := buildCommitments([][]uint8{raw.Commitment})[0]
	return FriLayerProof{
		FriWitness:   friWitness,
		Decommitment: decommitment,
		Commitment:   commitment,
	}
}

func buildLastLayerPoly(raw LinePolyRaw) circle.LinePoly {
	coeffs := m31.NewQM31FromArrays(raw.Coeffs[0])
	return circle.LinePoly{
		Coeffs:  []m31.QM31{coeffs},
		LogSize: uints.NewU8(raw.LogSize),
	}
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

	mask := new(big.Int).Lsh(big.NewInt(1), BitsPerM31)
	mask.Sub(mask, big.NewInt(1))

	// Split the big integer into NM31InFelt252 M31 limbs
	var result Felt252Value
	for i := 0; i < NM31InFelt252; i++ {
		tmp.And(acc, mask)
		result[i] = m31.NewM31Unchecked(tmp.Uint64())
		acc.Rsh(acc, BitsPerM31)
	}

	return result
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

// ProofFixturePath returns the path to the proof fixture with the given name.
func ProofFixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "test_data", name)
}

// ShapeFixturePath returns the path to the circuit shape fixture derived from the proof fixture.
func ShapeFixturePath(name string) string {
	proofPath := ProofFixturePath(name)
	dir := filepath.Dir(proofPath)
	base := filepath.Base(proofPath)
	ext := filepath.Ext(base)
	shapeName := strings.TrimSuffix(base, ext) + "_shape.json"
	return filepath.Join(dir, shapeName)
}
