package variables

import (
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

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

// BuildProof builds a Proof (used in circuits) from a ProofRaw (from json)
func BuildProof(proofRaw ProofRaw) Proof {
	var proof Proof

	claim := BuildClaim(&proofRaw.Claim)
	proof.Claim = claim
	proof.InteractionPow = uints.NewU64(proofRaw.InteractionPow)
	proof.InteractionClaim = BuildInteractionClaim(&proofRaw.InteractionClaim)
	proof.StarkProof = BuildStarkProof(&proofRaw.StarkProof)
	proof.CircuitHints = buildCircuitHints(proofRaw.CircuitHints)

	return proof
}

// ╔══════════════════════════════════╗
// ║       Circuit Data Building      ║
// ╚══════════════════════════════════╝

// BuildCircuitData builds a CircuitData from a ProofRaw
func BuildCircuitData(proofRaw *ProofRaw) CircuitData {
	if proofRaw == nil {
		return CircuitData{}
	}

	// Set all components presence to false
	componentConfig := ComponentConfig{}
	for i := range componentConfig {
		componentConfig[i] = false
	}

	nColumnsPerLogSize := make([][]int, 4)
	for i := range nColumnsPerLogSize {
		nColumnsPerLogSize[i] = make([]int, 32)
	}

	// Build opcodes
	if len(proofRaw.Claim.Opcodes.Add) > 0 {
		componentConfig[0] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Add[0].LogSize)] += cairo_components.AddOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Add[0].LogSize)] += cairo_components.AddOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.AddSmall) > 0 {
		componentConfig[1] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.AddSmall[0].LogSize)] += cairo_components.AddSmallOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.AddSmall[0].LogSize)] += cairo_components.AddSmallOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.AddAp) > 0 {
		componentConfig[2] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.AddAp[0].LogSize)] += cairo_components.AddApOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.AddAp[0].LogSize)] += cairo_components.AddApOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.AssertEq) > 0 {
		componentConfig[3] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.AssertEq[0].LogSize)] += cairo_components.AssertEqOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.AssertEq[0].LogSize)] += cairo_components.AssertEqOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.AssertEqImm) > 0 {
		componentConfig[4] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.AssertEqImm[0].LogSize)] += cairo_components.AssertEqImmOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.AssertEqImm[0].LogSize)] += cairo_components.AssertEqImmOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.AssertEqDoubleDeref) > 0 {
		componentConfig[5] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.AssertEqDoubleDeref[0].LogSize)] += cairo_components.AssertEqDoubleDerefOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.AssertEqDoubleDeref[0].LogSize)] += cairo_components.AssertEqDoubleDerefOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Blake) > 0 {
		componentConfig[6] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Blake[0].LogSize)] += cairo_components.BlakeCompressTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Blake[0].LogSize)] += cairo_components.BlakeCompressInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Call) > 0 {
		componentConfig[7] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Call[0].LogSize)] += cairo_components.CallOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Call[0].LogSize)] += cairo_components.CallOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.CallRelImm) > 0 {
		componentConfig[8] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.CallRelImm[0].LogSize)] += cairo_components.CallRelImmOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.CallRelImm[0].LogSize)] += cairo_components.CallRelImmOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Generic) > 0 {
		componentConfig[9] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Generic[0].LogSize)] += cairo_components.GenericOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Generic[0].LogSize)] += cairo_components.GenericOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Jnz) > 0 {
		componentConfig[10] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Jnz[0].LogSize)] += cairo_components.JnzOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Jnz[0].LogSize)] += cairo_components.JnzOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.JnzTaken) > 0 {
		componentConfig[11] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.JnzTaken[0].LogSize)] += cairo_components.JnzTakenOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.JnzTaken[0].LogSize)] += cairo_components.JnzTakenOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Jump) > 0 {
		componentConfig[12] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Jump[0].LogSize)] += cairo_components.JumpOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Jump[0].LogSize)] += cairo_components.JumpOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.JumpDoubleDeref) > 0 {
		componentConfig[13] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.JumpDoubleDeref[0].LogSize)] += cairo_components.JumpDoubleDerefOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.JumpDoubleDeref[0].LogSize)] += cairo_components.JumpDoubleDerefOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.JumpRel) > 0 {
		componentConfig[14] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.JumpRel[0].LogSize)] += cairo_components.JumpRelOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.JumpRel[0].LogSize)] += cairo_components.JumpRelOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.JumpRelImm) > 0 {
		componentConfig[15] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.JumpRelImm[0].LogSize)] += cairo_components.JumpRelImmOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.JumpRelImm[0].LogSize)] += cairo_components.JumpRelImmOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Mul) > 0 {
		componentConfig[16] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Mul[0].LogSize)] += cairo_components.MulOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Mul[0].LogSize)] += cairo_components.MulOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.MulSmall) > 0 {
		componentConfig[17] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.MulSmall[0].LogSize)] += cairo_components.MulSmallOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.MulSmall[0].LogSize)] += cairo_components.MulSmallOpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Qm31) > 0 {
		componentConfig[18] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Qm31[0].LogSize)] += cairo_components.Qm31OpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Qm31[0].LogSize)] += cairo_components.Qm31OpcodeInteractionColumns
	}
	if len(proofRaw.Claim.Opcodes.Ret) > 0 {
		componentConfig[19] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.Opcodes.Ret[0].LogSize)] += cairo_components.RetOpcodeTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.Opcodes.Ret[0].LogSize)] += cairo_components.RetOpcodeInteractionColumns
	}

	// Build verify instruction
	componentConfig[20] = true
	nColumnsPerLogSize[1][int(proofRaw.Claim.VerifyInstruction.LogSize)] += cairo_components.VerifyInstructionTraceColumns
	nColumnsPerLogSize[2][int(proofRaw.Claim.VerifyInstruction.LogSize)] += cairo_components.VerifyInstructionInteractionColumns

	// Build Blake context
	if proofRaw.Claim.BlakeContext.Claim != nil {
		componentConfig[21] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.BlakeContext.Claim.BlakeRound.LogSize)] += cairo_components.BlakeRoundTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.BlakeContext.Claim.BlakeRound.LogSize)] += cairo_components.BlakeRoundInteractionColumns
		componentConfig[22] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.BlakeContext.Claim.BlakeG.LogSize)] += cairo_components.BlakeGTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.BlakeContext.Claim.BlakeG.LogSize)] += cairo_components.BlakeGInteractionColumns
		componentConfig[23] = true
		nColumnsPerLogSize[1][cairo_components.BlakeRoundSigmaLogSize] += cairo_components.BlakeRoundSigmaTraceColumns
		nColumnsPerLogSize[2][cairo_components.BlakeRoundSigmaLogSize] += cairo_components.BlakeRoundSigmaInteractionColumns
		componentConfig[24] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.BlakeContext.Claim.TripleXor32.LogSize)] += cairo_components.TripleXor32TraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.BlakeContext.Claim.TripleXor32.LogSize)] += cairo_components.TripleXor32InteractionColumns
		componentConfig[25] = true
		nColumnsPerLogSize[1][cairo_components.VerifyBitwiseXor12LogSize] += cairo_components.VerifyBitwiseXor12TraceColumns
		nColumnsPerLogSize[2][cairo_components.VerifyBitwiseXor12LogSize] += cairo_components.VerifyBitwiseXor12InteractionColumns
	}

	// Build builtins
	if proofRaw.Claim.Builtins["add_mod_builtin"] != nil {
		componentConfig[26] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["add_mod_builtin"].LogSize)] += cairo_components.AddModBuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["add_mod_builtin"].LogSize)] += cairo_components.AddModBuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["bitwise_builtin"] != nil {
		componentConfig[27] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["bitwise_builtin"].LogSize)] += cairo_components.BitwiseBuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["bitwise_builtin"].LogSize)] += cairo_components.BitwiseBuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["mul_mod_builtin"] != nil {
		componentConfig[28] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["mul_mod_builtin"].LogSize)] += cairo_components.MulModBuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["mul_mod_builtin"].LogSize)] += cairo_components.MulModBuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["pedersen_builtin"] != nil {
		componentConfig[29] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["pedersen_builtin"].LogSize)] += cairo_components.PedersenBuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["pedersen_builtin"].LogSize)] += cairo_components.PedersenBuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["poseidon_builtin"] != nil {
		componentConfig[30] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["poseidon_builtin"].LogSize)] += cairo_components.PoseidonBuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["poseidon_builtin"].LogSize)] += cairo_components.PoseidonBuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["range_check_96_builtin"] != nil {
		componentConfig[31] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["range_check_96_builtin"].LogSize)] += cairo_components.RangeCheck96BuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["range_check_96_builtin"].LogSize)] += cairo_components.RangeCheck96BuiltinInteractionColumns
	}
	if proofRaw.Claim.Builtins["range_check_128_builtin"] != nil {
		componentConfig[32] = true
		nColumnsPerLogSize[1][int(*proofRaw.Claim.Builtins["range_check_128_builtin"].LogSize)] += cairo_components.RangeCheck128BuiltinTraceColumns
		nColumnsPerLogSize[2][int(*proofRaw.Claim.Builtins["range_check_128_builtin"].LogSize)] += cairo_components.RangeCheck128BuiltinInteractionColumns
	}

	// Build pedersen context
	if proofRaw.Claim.PedersenContext.Claim != nil {
		componentConfig[33] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.PedersenContext.Claim["partial_ec_mul"].LogSize)] += cairo_components.PartialEcMulTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.PedersenContext.Claim["partial_ec_mul"].LogSize)] += cairo_components.PartialEcMulInteractionColumns
		componentConfig[34] = true
		nColumnsPerLogSize[1][cairo_components.PedersenPointsTableLogSize] += cairo_components.PedersenPointsTableTraceColumns
		nColumnsPerLogSize[2][cairo_components.PedersenPointsTableLogSize] += cairo_components.PedersenPointsTableInteractionColumns
	}

	// Build poseidon context
	if proofRaw.Claim.PoseidonContext.Claim != nil {
		componentConfig[35] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.PoseidonContext.Claim.Poseidon3PartialRoundsChain.LogSize)] += cairo_components.Poseidon3PartialRoundsTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.PoseidonContext.Claim.Poseidon3PartialRoundsChain.LogSize)] += cairo_components.Poseidon3PartialRoundsInteractionColumns
		componentConfig[36] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.PoseidonContext.Claim.PoseidonFullRoundChain.LogSize)] += cairo_components.PoseidonFullRoundTraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.PoseidonContext.Claim.PoseidonFullRoundChain.LogSize)] += cairo_components.PoseidonFullRoundInteractionColumns
		componentConfig[37] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.PoseidonContext.Claim.Cube252.LogSize)] += cairo_components.Cube252TraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.PoseidonContext.Claim.Cube252.LogSize)] += cairo_components.Cube252InteractionColumns
		componentConfig[38] = true
		nColumnsPerLogSize[1][cairo_components.PoseidonRoundKeysLogSize] += cairo_components.PoseidonRoundKeysTraceColumns
		nColumnsPerLogSize[2][cairo_components.PoseidonRoundKeysLogSize] += cairo_components.PoseidonRoundKeysInteractionColumns
		componentConfig[39] = true
		nColumnsPerLogSize[1][int(proofRaw.Claim.PoseidonContext.Claim.RangeCheckFelt252Width27.LogSize)] += cairo_components.RangeCheckFelt252Width27TraceColumns
		nColumnsPerLogSize[2][int(proofRaw.Claim.PoseidonContext.Claim.RangeCheckFelt252Width27.LogSize)] += cairo_components.RangeCheckFelt252Width27InteractionColumns
	}

	// Build memory address to id component
	componentConfig[40] = true
	nColumnsPerLogSize[1][int(proofRaw.Claim.MemoryAddressToId.LogSize)] += cairo_components.MemoryAddressToIdTraceColumns
	nColumnsPerLogSize[2][int(proofRaw.Claim.MemoryAddressToId.LogSize)] += cairo_components.MemoryAddressToIdInteractionColumns

	// Build ID to Big Big memory components
	// TODO: Handle multiple id to big tables
	componentConfig[41] = true
	nColumnsPerLogSize[1][int(proofRaw.Claim.MemoryIDToValue.BigLogSizes[0])] += cairo_components.MemoryIdToBigBigTraceCols
	nColumnsPerLogSize[2][int(proofRaw.Claim.MemoryIDToValue.BigLogSizes[0])] += cairo_components.MemoryIdToBigBigInteractionColumns

	// Build ID to Big Small memory components
	componentConfig[42] = true
	nColumnsPerLogSize[1][int(proofRaw.Claim.MemoryIDToValue.SmallLogSize)] += cairo_components.MemoryIdToBigSmallTraceCols
	nColumnsPerLogSize[2][int(proofRaw.Claim.MemoryIDToValue.SmallLogSize)] += cairo_components.MemoryIdToBigSmallInteractionColumns

	// Build range checks
	componentConfig[43] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck6LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck6LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[44] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck8LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck8LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[45] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck11LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck11LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[46] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck12LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck12LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[47] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck18LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck18LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[48] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck19LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck19LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[49] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck43LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck43LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[50] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck44LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck44LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[51] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck54LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck54LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[52] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck99LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck99LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[53] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck725LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck725LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[54] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck3663LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck3663LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[55] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck4444LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck4444LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[56] = true
	nColumnsPerLogSize[1][cairo_components.RangeCheck33333LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.RangeCheck33333LogSize] += cairo_components.LookupInteractionColumns

	// Build bitwise XOR
	componentConfig[57] = true
	nColumnsPerLogSize[1][cairo_components.VerifyBitwiseXor4LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.VerifyBitwiseXor4LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[58] = true
	nColumnsPerLogSize[1][cairo_components.VerifyBitwiseXor7LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.VerifyBitwiseXor7LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[59] = true
	nColumnsPerLogSize[1][cairo_components.VerifyBitwiseXor8LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.VerifyBitwiseXor8LogSize] += cairo_components.LookupInteractionColumns
	componentConfig[60] = true
	nColumnsPerLogSize[1][cairo_components.VerifyBitwiseXor9LogSize] += cairo_components.LookupTraceColumns
	nColumnsPerLogSize[2][cairo_components.VerifyBitwiseXor9LogSize] += cairo_components.LookupInteractionColumns

	// Preprocessed columns log sizes
	nColumnsPerLogSize[0][24] += 1
	nColumnsPerLogSize[0][23] += 57
	nColumnsPerLogSize[0][22] += 1
	nColumnsPerLogSize[0][21] += 1
	nColumnsPerLogSize[0][20] += 4
	nColumnsPerLogSize[0][19] += 1
	nColumnsPerLogSize[0][18] += 10
	nColumnsPerLogSize[0][17] += 1
	nColumnsPerLogSize[0][16] += 8
	nColumnsPerLogSize[0][15] += 6
	nColumnsPerLogSize[0][14] += 7
	nColumnsPerLogSize[0][13] += 1
	nColumnsPerLogSize[0][12] += 1
	nColumnsPerLogSize[0][11] += 1
	nColumnsPerLogSize[0][10] += 1
	nColumnsPerLogSize[0][9] += 3
	nColumnsPerLogSize[0][8] += 6
	nColumnsPerLogSize[0][7] += 3
	nColumnsPerLogSize[0][6] += 31
	nColumnsPerLogSize[0][5] += 1
	nColumnsPerLogSize[0][4] += 17

	// CP log size
	maxLogSize := -1
	for i := 31; i >= 0; i-- {
		if nColumnsPerLogSize[1][i] > 0 || nColumnsPerLogSize[2][i] > 0 {
			maxLogSize = i
			break
		}
	}
	nColumnsPerLogSize[3][maxLogSize+1] += 4

	// bounds length (number of unique log sizes)
	uniqueLogSizes := make(map[int]struct{})
	for _, tree := range nColumnsPerLogSize {
		for logSize := range tree {
			if logSize > 0 {
				uniqueLogSizes[logSize] = struct{}{}
			}
		}
	}
	boundsLengthCount := len(uniqueLogSizes)

	return CircuitData{
		ComponentConfig:    componentConfig,
		NColumnsPerLogSize: nColumnsPerLogSize,
		BoundsLength:       boundsLengthCount,
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

	claim := CairoClaim{}

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

	var interactionClaim CairoInteractionClaim

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
// ║      Circuit Hints Building      ║
// ╚══════════════════════════════════╝

func buildCircuitHints(raw CircuitHintsRaw) CircuitHints {
	hints := CircuitHints{}

	queryMap := make(map[int][]int, len(raw.QueryPositionsByLogSize))
	maxLogSize := -1
	for logSizeStr, positions := range raw.QueryPositionsByLogSize {
		logSize, err := strconv.ParseUint(logSizeStr, 10, 32)
		if err != nil {
			panic(err)
		}
		intLogSize := int(logSize)
		if intLogSize > maxLogSize {
			maxLogSize = intLogSize
		}
		queryMap[intLogSize] = append([]int(nil), positions...)
	}

	queries := make([][]int, maxLogSize+1)
	for log := 0; log <= maxLogSize; log++ {
		if positions, ok := queryMap[log]; ok {
			queries[log] = positions
			continue
		}
		queries[log] = []int{}
	}

	hints.Queries = queries
	return hints
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
