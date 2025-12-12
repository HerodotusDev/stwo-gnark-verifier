package variables

import (
	"reflect"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

// ╔══════════════════════════════════╗
// ║        Interaction Claim         ║
// ╚══════════════════════════════════╝

// CairoInteractionClaim contains the claimed sums for each component
type CairoInteractionClaim struct {
	// Opcodes
	Add                 cairo_components.AddOpcodeInteractionClaim
	AddSmall            cairo_components.AddSmallOpcodeInteractionClaim
	AddAp               cairo_components.AddApOpcodeInteractionClaim
	AssertEq            cairo_components.AssertEqOpcodeInteractionClaim
	AssertEqImm         cairo_components.AssertEqImmOpcodeInteractionClaim
	AssertEqDoubleDeref cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim
	Blake               cairo_components.BlakeCompressOpcodeInteractionClaim
	Call                cairo_components.CallOpcodeInteractionClaim
	CallRelImm          cairo_components.CallRelImmOpcodeInteractionClaim
	Generic             cairo_components.GenericOpcodeInteractionClaim
	Jnz                 cairo_components.JnzOpcodeInteractionClaim
	JnzTaken            cairo_components.JnzTakenOpcodeInteractionClaim
	Jump                cairo_components.JumpOpcodeInteractionClaim
	JumpDoubleDeref     cairo_components.JumpDoubleDerefOpcodeInteractionClaim
	JumpRel             cairo_components.JumpRelOpcodeInteractionClaim
	JumpRelImm          cairo_components.JumpRelImmOpcodeInteractionClaim
	Mul                 cairo_components.MulOpcodeInteractionClaim
	MulSmall            cairo_components.MulSmallOpcodeInteractionClaim
	Qm31                cairo_components.Qm31OpcodeInteractionClaim
	Ret                 cairo_components.RetOpcodeInteractionClaim

	// Verify Instruction
	VerifyInstruction cairo_components.VerifyInstructionInteractionClaim

	// Blake context
	BlakeRound         cairo_components.BlakeRoundInteractionClaim
	BlakeG             cairo_components.BlakeGInteractionClaim
	BlakeRoundSigma    cairo_components.BlakeRoundSigmaInteractionClaim
	TripleXor32        cairo_components.TripleXor32InteractionClaim
	VerifyBitwiseXor12 cairo_components.VerifyBitwiseXor12InteractionClaim

	// Builtins
	AddModBuiltin   cairo_components.AddModBuiltinInteractionClaim
	BitwiseBuiltin  cairo_components.BitwiseBuiltinInteractionClaim
	MulModBuiltin   cairo_components.MulModBuiltinInteractionClaim
	PedersenBuiltin cairo_components.PedersenBuiltinInteractionClaim
	PoseidonBuiltin cairo_components.PoseidonBuiltinInteractionClaim
	RangeCheck96    cairo_components.RangeCheck96BuiltinInteractionClaim
	RangeCheck128   cairo_components.RangeCheck128BuiltinInteractionClaim

	// Pedersen context
	PartialEcMul        cairo_components.PartialEcMulInteractionClaim
	PedersenPointsTable cairo_components.PedersenPointsTableInteractionClaim

	// Poseidon context
	Poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainInteractionClaim
	PoseidonFullRoundChain      cairo_components.PoseidonFullRoundChainInteractionClaim
	Cube252                     cairo_components.Cube252InteractionClaim
	PoseidonRoundKeys           cairo_components.PoseidonRoundKeysInteractionClaim
	RangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27InteractionClaim

	// Memory
	MemoryAddressToID  cairo_components.MemoryAddressToIDInteractionClaim
	MemoryIDToBigBig   cairo_components.MemoryIDToBigBigInteractionClaim
	MemoryIDToBigSmall cairo_components.MemoryIDToBigSmallInteractionClaim

	// Range checks
	RC6     cairo_components.RangeCheck6InteractionClaim
	RC8     cairo_components.RangeCheck8InteractionClaim
	RC11    cairo_components.RangeCheck11InteractionClaim
	RC12    cairo_components.RangeCheck12InteractionClaim
	RC18    cairo_components.RangeCheck18InteractionClaim
	RC19    cairo_components.RangeCheck19InteractionClaim
	RC43    cairo_components.RangeCheck43InteractionClaim
	RC44    cairo_components.RangeCheck44InteractionClaim
	RC54    cairo_components.RangeCheck54InteractionClaim
	RC99    cairo_components.RangeCheck99InteractionClaim
	RC725   cairo_components.RangeCheck725InteractionClaim
	RC3663  cairo_components.RangeCheck3663InteractionClaim
	RC4444  cairo_components.RangeCheck4444InteractionClaim
	RC33333 cairo_components.RangeCheck33333InteractionClaim

	// Bitwise XOR
	VerifyBitwiseXor4 cairo_components.VerifyBitwiseXor4InteractionClaim
	VerifyBitwiseXor7 cairo_components.VerifyBitwiseXor7InteractionClaim
	VerifyBitwiseXor8 cairo_components.VerifyBitwiseXor8InteractionClaim
	VerifyBitwiseXor9 cairo_components.VerifyBitwiseXor9InteractionClaim
}

// Default returns a CairoInteractionClaim with all claim fields initialized to zero values.
// This is used to initialize the circuit with default values if not, gnark will panic due to nil pointers for unused components.
func (CairoInteractionClaim) Default() CairoInteractionClaim {
	var claim CairoInteractionClaim
	zeroInteractionValues(reflect.ValueOf(&claim))
	return claim
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildInteractionClaim builds a CairoInteractionClaim from a InteractionClaimRaw
func BuildInteractionClaim(interactionClaimRaw *InteractionClaimRaw) CairoInteractionClaim {
	if interactionClaimRaw == nil {
		return CairoInteractionClaim{}
	}

	// Using default to prevent nil pointers for unused components
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
	interactionClaim.MemoryAddressToID = cairo_components.MemoryAddressToIDInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryAddressToID.ClaimedSum)}

	// Memory ID to value interaction claim
	// TODO: handle multiple big claims
	interactionClaim.MemoryIDToBigBig = cairo_components.MemoryIDToBigBigInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryIDToValue.BigClaimedSums[0])}
	interactionClaim.MemoryIDToBigSmall = cairo_components.MemoryIDToBigSmallInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryIDToValue.SmallClaimedSum)}

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
// ║              Mixing              ║
// ╚══════════════════════════════════╝

// MixInto absorbs the Cairo interaction claim into the transcript channel.
// This is highly order dependent, so the components need to be correctly ordered
func (claim CairoInteractionClaim) MixInto(ch *channel.Channel, circuitData CircuitData) {

	// Mix opcodes
	if circuitData.ComponentConfig[0] {
		ch.MixFelts([]m31.QM31{claim.Add.ClaimedSum})
	}
	if circuitData.ComponentConfig[1] {
		ch.MixFelts([]m31.QM31{claim.AddSmall.ClaimedSum})
	}
	if circuitData.ComponentConfig[2] {
		ch.MixFelts([]m31.QM31{claim.AddAp.ClaimedSum})
	}
	if circuitData.ComponentConfig[3] {
		ch.MixFelts([]m31.QM31{claim.AssertEq.ClaimedSum})
	}
	if circuitData.ComponentConfig[4] {
		ch.MixFelts([]m31.QM31{claim.AssertEqImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[5] {
		ch.MixFelts([]m31.QM31{claim.AssertEqDoubleDeref.ClaimedSum})
	}
	if circuitData.ComponentConfig[6] {
		ch.MixFelts([]m31.QM31{claim.Blake.ClaimedSum})
	}
	if circuitData.ComponentConfig[7] {
		ch.MixFelts([]m31.QM31{claim.Call.ClaimedSum})
	}
	if circuitData.ComponentConfig[8] {
		ch.MixFelts([]m31.QM31{claim.CallRelImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[9] {
		ch.MixFelts([]m31.QM31{claim.Generic.ClaimedSum})
	}
	if circuitData.ComponentConfig[10] {
		ch.MixFelts([]m31.QM31{claim.Jnz.ClaimedSum})
	}
	if circuitData.ComponentConfig[11] {
		ch.MixFelts([]m31.QM31{claim.JnzTaken.ClaimedSum})
	}
	if circuitData.ComponentConfig[12] {
		ch.MixFelts([]m31.QM31{claim.Jump.ClaimedSum})
	}
	if circuitData.ComponentConfig[13] {
		ch.MixFelts([]m31.QM31{claim.JumpDoubleDeref.ClaimedSum})
	}
	if circuitData.ComponentConfig[14] {
		ch.MixFelts([]m31.QM31{claim.JumpRel.ClaimedSum})
	}
	if circuitData.ComponentConfig[15] {
		ch.MixFelts([]m31.QM31{claim.JumpRelImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[16] {
		ch.MixFelts([]m31.QM31{claim.Mul.ClaimedSum})
	}
	if circuitData.ComponentConfig[17] {
		ch.MixFelts([]m31.QM31{claim.MulSmall.ClaimedSum})
	}
	if circuitData.ComponentConfig[18] {
		ch.MixFelts([]m31.QM31{claim.Qm31.ClaimedSum})
	}
	if circuitData.ComponentConfig[19] {
		ch.MixFelts([]m31.QM31{claim.Ret.ClaimedSum})
	}

	// Mix verify instruction
	if circuitData.ComponentConfig[20] {
		ch.MixFelts([]m31.QM31{claim.VerifyInstruction.ClaimedSum})
	}

	// Mix Blake context
	if circuitData.ComponentConfig[21] {
		ch.MixFelts([]m31.QM31{claim.BlakeRound.ClaimedSum})
	}
	if circuitData.ComponentConfig[22] {
		ch.MixFelts([]m31.QM31{claim.BlakeG.ClaimedSum})
	}
	if circuitData.ComponentConfig[23] {
		ch.MixFelts([]m31.QM31{claim.BlakeRoundSigma.ClaimedSum})
	}
	if circuitData.ComponentConfig[24] {
		ch.MixFelts([]m31.QM31{claim.TripleXor32.ClaimedSum})
	}
	if circuitData.ComponentConfig[25] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor12.ClaimedSum})
	}

	// Mix builtins
	if circuitData.ComponentConfig[26] {
		ch.MixFelts([]m31.QM31{claim.AddModBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[27] {
		ch.MixFelts([]m31.QM31{claim.BitwiseBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[28] {
		ch.MixFelts([]m31.QM31{claim.MulModBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[29] {
		ch.MixFelts([]m31.QM31{claim.PedersenBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[30] {
		ch.MixFelts([]m31.QM31{claim.PoseidonBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[31] {
		ch.MixFelts([]m31.QM31{claim.RangeCheck96.ClaimedSum})
	}
	if circuitData.ComponentConfig[32] {
		ch.MixFelts([]m31.QM31{claim.RangeCheck128.ClaimedSum})
	}

	// Mix pedersen context
	if circuitData.ComponentConfig[33] {
		ch.MixFelts([]m31.QM31{claim.PartialEcMul.ClaimedSum})
	}
	if circuitData.ComponentConfig[34] {
		ch.MixFelts([]m31.QM31{claim.PedersenPointsTable.ClaimedSum})
	}

	// Mix poseidon context
	if circuitData.ComponentConfig[35] {
		ch.MixFelts([]m31.QM31{claim.Poseidon3PartialRoundsChain.ClaimedSum})
	}
	if circuitData.ComponentConfig[36] {
		ch.MixFelts([]m31.QM31{claim.PoseidonFullRoundChain.ClaimedSum})
	}
	if circuitData.ComponentConfig[37] {
		ch.MixFelts([]m31.QM31{claim.Cube252.ClaimedSum})
	}
	if circuitData.ComponentConfig[38] {
		ch.MixFelts([]m31.QM31{claim.PoseidonRoundKeys.ClaimedSum})
	}
	if circuitData.ComponentConfig[39] {
		ch.MixFelts([]m31.QM31{claim.RangeCheckFelt252Width27.ClaimedSum})
	}

	// Mix memory components
	if circuitData.ComponentConfig[40] {
		ch.MixFelts([]m31.QM31{claim.MemoryAddressToID.ClaimedSum})
	}
	if circuitData.ComponentConfig[41] {
		ch.MixFelts([]m31.QM31{claim.MemoryIDToBigBig.ClaimedSum})
	}
	if circuitData.ComponentConfig[42] {
		ch.MixFelts([]m31.QM31{claim.MemoryIDToBigSmall.ClaimedSum})
	}

	// Mix range checks
	if circuitData.ComponentConfig[43] {
		ch.MixFelts([]m31.QM31{claim.RC6.ClaimedSum})
	}
	if circuitData.ComponentConfig[44] {
		ch.MixFelts([]m31.QM31{claim.RC8.ClaimedSum})
	}
	if circuitData.ComponentConfig[45] {
		ch.MixFelts([]m31.QM31{claim.RC11.ClaimedSum})
	}
	if circuitData.ComponentConfig[46] {
		ch.MixFelts([]m31.QM31{claim.RC12.ClaimedSum})
	}
	if circuitData.ComponentConfig[47] {
		ch.MixFelts([]m31.QM31{claim.RC18.ClaimedSum})
	}
	if circuitData.ComponentConfig[48] {
		ch.MixFelts([]m31.QM31{claim.RC19.ClaimedSum})
	}
	if circuitData.ComponentConfig[49] {
		ch.MixFelts([]m31.QM31{claim.RC43.ClaimedSum})
	}
	if circuitData.ComponentConfig[50] {
		ch.MixFelts([]m31.QM31{claim.RC44.ClaimedSum})
	}
	if circuitData.ComponentConfig[51] {
		ch.MixFelts([]m31.QM31{claim.RC54.ClaimedSum})
	}
	if circuitData.ComponentConfig[52] {
		ch.MixFelts([]m31.QM31{claim.RC99.ClaimedSum})
	}
	if circuitData.ComponentConfig[53] {
		ch.MixFelts([]m31.QM31{claim.RC725.ClaimedSum})
	}
	if circuitData.ComponentConfig[54] {
		ch.MixFelts([]m31.QM31{claim.RC3663.ClaimedSum})
	}
	if circuitData.ComponentConfig[55] {
		ch.MixFelts([]m31.QM31{claim.RC4444.ClaimedSum})
	}
	if circuitData.ComponentConfig[56] {
		ch.MixFelts([]m31.QM31{claim.RC33333.ClaimedSum})
	}

	// Mix verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor4.ClaimedSum})
	}
	if circuitData.ComponentConfig[58] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor7.ClaimedSum})
	}
	if circuitData.ComponentConfig[59] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor8.ClaimedSum})
	}
	if circuitData.ComponentConfig[60] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor9.ClaimedSum})
	}
}
