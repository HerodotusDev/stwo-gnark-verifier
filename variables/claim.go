package variables

import (
	"reflect"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║         Structure Types          ║
// ╚══════════════════════════════════╝

// CairoClaim contains the public data and the log sizes for each component
type CairoClaim struct {
	PublicData PublicData

	// Opcodes
	Add                 cairo_components.AddOpcodeClaim
	AddSmall            cairo_components.AddSmallOpcodeClaim
	AddAp               cairo_components.AddApOpcodeClaim
	AssertEq            cairo_components.AssertEqOpcodeClaim
	AssertEqImm         cairo_components.AssertEqImmOpcodeClaim
	AssertEqDoubleDeref cairo_components.AssertEqDoubleDerefOpcodeClaim
	Blake               cairo_components.BlakeCompressOpcodeClaim
	Call                cairo_components.CallOpcodeClaim
	CallRelImm          cairo_components.CallRelImmOpcodeClaim
	Generic             cairo_components.GenericOpcodeClaim
	Jnz                 cairo_components.JnzOpcodeClaim
	JnzTaken            cairo_components.JnzTakenOpcodeClaim
	Jump                cairo_components.JumpOpcodeClaim
	JumpDoubleDeref     cairo_components.JumpDoubleDerefOpcodeClaim
	JumpRel             cairo_components.JumpRelOpcodeClaim
	JumpRelImm          cairo_components.JumpRelImmOpcodeClaim
	Mul                 cairo_components.MulOpcodeClaim
	MulSmall            cairo_components.MulSmallOpcodeClaim
	Qm31                cairo_components.Qm31OpcodeClaim
	Ret                 cairo_components.RetOpcodeClaim

	// Verify Instruction
	VerifyInstruction cairo_components.VerifyInstructionClaim

	// Blake context
	BlakeRound         cairo_components.BlakeRoundClaim
	BlakeG             cairo_components.BlakeGClaim
	BlakeRoundSigma    cairo_components.BlakeRoundSigmaClaim
	TripleXor32        cairo_components.TripleXor32Claim
	VerifyBitwiseXor12 cairo_components.VerifyBitwiseXor12Claim

	// Builtins
	AddModBuiltin   cairo_components.AddModBuiltinClaim
	BitwiseBuiltin  cairo_components.BitwiseBuiltinClaim
	MulModBuiltin   cairo_components.MulModBuiltinClaim
	PedersenBuiltin cairo_components.PedersenBuiltinClaim
	PoseidonBuiltin cairo_components.PoseidonBuiltinClaim
	RangeCheck96    cairo_components.RangeCheck96BuiltinClaim
	RangeCheck128   cairo_components.RangeCheck128BuiltinClaim

	// Pedersen context
	PartialEcMul        cairo_components.PartialEcMulClaim
	PedersenPointsTable cairo_components.PedersenPointsTableClaim

	// Poseidon context
	Poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainClaim
	PoseidonFullRoundChain      cairo_components.PoseidonFullRoundChainClaim
	Cube252                     cairo_components.Cube252Claim
	PoseidonRoundKeys           cairo_components.PoseidonRoundKeysClaim
	RangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27Claim

	// Memory
	MemoryAddressToID  cairo_components.MemoryAddressToIDClaim
	MemoryIDToBigBig   cairo_components.MemoryIDToBigBigClaim
	MemoryIDToBigSmall cairo_components.MemoryIDToBigSmallClaim

	// Range checks
	RC6     cairo_components.RangeCheck6Claim
	RC8     cairo_components.RangeCheck8Claim
	RC11    cairo_components.RangeCheck11Claim
	RC12    cairo_components.RangeCheck12Claim
	RC18    cairo_components.RangeCheck18Claim
	RC19    cairo_components.RangeCheck19Claim
	RC43    cairo_components.RangeCheck43Claim
	RC44    cairo_components.RangeCheck44Claim
	RC54    cairo_components.RangeCheck54Claim
	RC99    cairo_components.RangeCheck99Claim
	RC725   cairo_components.RangeCheck725Claim
	RC3663  cairo_components.RangeCheck3663Claim
	RC4444  cairo_components.RangeCheck4444Claim
	RC33333 cairo_components.RangeCheck33333Claim

	// Bitwise XOR
	VerifyBitwiseXor4 cairo_components.VerifyBitwiseXor4Claim
	VerifyBitwiseXor7 cairo_components.VerifyBitwiseXor7Claim
	VerifyBitwiseXor8 cairo_components.VerifyBitwiseXor8Claim
	VerifyBitwiseXor9 cairo_components.VerifyBitwiseXor9Claim
}

// ╔══════════════════════════════════╗
// ║         Claim Building           ║
// ╚══════════════════════════════════╝

// Default returns a CairoClaim with all claim fields initialized to zero values except PublicData.
// This is used to initialize the circuit with default values if not, gnark will panic due to nil pointers for unused components.
func (CairoClaim) Default() CairoClaim {
	var claim CairoClaim
	zeroFrontendVariables(reflect.ValueOf(&claim), true)
	return claim
}

// BuildClaim builds a CairoClaim from a ClaimRaw
func BuildClaim(claimRaw *ClaimRaw) CairoClaim {
	if claimRaw == nil {
		return CairoClaim{}
	}

	// Using default to prevent nil pointers for unused components
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
			LogSize:                   frontend.Variable(*claimRaw.Builtins["add_mod_builtin"].LogSize),
			AddModBuiltinSegmentStart: frontend.Variable(*claimRaw.Builtins["add_mod_builtin"].AddModBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["bitwise_builtin"] != nil {
		claim.BitwiseBuiltin = cairo_components.BitwiseBuiltinClaim{
			LogSize:                    frontend.Variable(*claimRaw.Builtins["bitwise_builtin"].LogSize),
			BitwiseBuiltinSegmentStart: frontend.Variable(*claimRaw.Builtins["bitwise_builtin"].BitwiseBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["mul_mod_builtin"] != nil {
		claim.MulModBuiltin = cairo_components.MulModBuiltinClaim{
			LogSize:                   frontend.Variable(*claimRaw.Builtins["mul_mod_builtin"].LogSize),
			MulModBuiltinSegmentStart: frontend.Variable(*claimRaw.Builtins["mul_mod_builtin"].MulModBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["pedersen_builtin"] != nil {
		claim.PedersenBuiltin = cairo_components.PedersenBuiltinClaim{
			LogSize:                     frontend.Variable(*claimRaw.Builtins["pedersen_builtin"].LogSize),
			PedersenBuiltinSegmentStart: frontend.Variable(*claimRaw.Builtins["pedersen_builtin"].PedersenBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["poseidon_builtin"] != nil {
		claim.PoseidonBuiltin = cairo_components.PoseidonBuiltinClaim{
			LogSize:                     frontend.Variable(*claimRaw.Builtins["poseidon_builtin"].LogSize),
			PoseidonBuiltinSegmentStart: frontend.Variable(*claimRaw.Builtins["poseidon_builtin"].PoseidonBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["range_check_96_builtin"] != nil {
		claim.RangeCheck96 = cairo_components.RangeCheck96BuiltinClaim{
			LogSize:                frontend.Variable(*claimRaw.Builtins["range_check_96_builtin"].LogSize),
			RangeCheckSegmentStart: frontend.Variable(*claimRaw.Builtins["range_check_96_builtin"].RangeCheckBuiltinSegmentStart),
		}
	}
	if claimRaw.Builtins["range_check_128_builtin"] != nil {
		claim.RangeCheck128 = cairo_components.RangeCheck128BuiltinClaim{
			LogSize:                frontend.Variable(*claimRaw.Builtins["range_check_128_builtin"].LogSize),
			RangeCheckSegmentStart: frontend.Variable(*claimRaw.Builtins["range_check_128_builtin"].RangeCheckBuiltinSegmentStart),
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
	claim.MemoryAddressToID = cairo_components.MemoryAddressToIDClaim{LogSize: frontend.Variable(claimRaw.MemoryAddressToID.LogSize)}

	// Build ID to Big Big memory components
	// TODO: Handle multiple id to big tables
	claim.MemoryIDToBigBig = cairo_components.MemoryIDToBigBigClaim{
		LogSize: frontend.Variable(claimRaw.MemoryIDToValue.BigLogSizes[0]),
		Offset:  uint32(0),
	}

	// Build ID to Big Small memory components
	claim.MemoryIDToBigSmall = cairo_components.MemoryIDToBigSmallClaim{
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
// ║              Mixing              ║
// ╚══════════════════════════════════╝

func (claim CairoClaim) MixIntoWithUAPI(ch *channel.Channel, api frontend.API, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64], circuitData CircuitData) {
	if ch == nil {
		panic("channel must not be nil")
	}
	if api == nil {
		panic("api must not be nil")
	}
	if uapi32 == nil || uapi64 == nil {
		panic("uapi must not be nil")
	}

	// Mix public data
	claim.PublicData.mixInto(ch, uapi32, uapi64)

	// Mix opcodes
	if circuitData.ComponentConfig[0] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Add.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[1] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddSmall.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[2] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddAp.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[3] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEq.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[4] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEqImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[5] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEqDoubleDeref.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[6] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Blake.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[7] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Call.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[8] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.CallRelImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[9] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Generic.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[10] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Jnz.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[11] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JnzTaken.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[12] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Jump.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[13] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpDoubleDeref.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[14] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpRel.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[15] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpRelImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[16] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Mul.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[17] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulSmall.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[18] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Qm31.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[19] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Ret.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}

	// Mix verify instruction
	if circuitData.ComponentConfig[20] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.VerifyInstruction.LogSize), uints.NewU32(0)})
	}

	// Mix Blake context
	if circuitData.ComponentConfig[21] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BlakeRound.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[22] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BlakeG.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[24] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.TripleXor32.LogSize), uints.NewU32(0)})
	}

	// Mix builtins
	if circuitData.ComponentConfig[26] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddModBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddModBuiltin.AddModBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[27] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BitwiseBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BitwiseBuiltin.BitwiseBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[28] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulModBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulModBuiltin.MulModBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[29] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PedersenBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PedersenBuiltin.PedersenBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[30] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonBuiltin.PoseidonBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[31] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck96.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck96.RangeCheckSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[32] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck128.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck128.RangeCheckSegmentStart), uints.NewU32(0)})
	}

	// Mix pedersen context
	if circuitData.ComponentConfig[33] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PartialEcMul.LogSize), uints.NewU32(0)})
	}

	// Mix poseidon context
	if circuitData.ComponentConfig[35] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Poseidon3PartialRoundsChain.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[36] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonFullRoundChain.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[37] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Cube252.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[39] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheckFelt252Width27.LogSize), uints.NewU32(0)})
	}

	// Mix memory components
	if circuitData.ComponentConfig[40] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryAddressToID.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[41] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryIDToBigBig.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[42] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryIDToBigSmall.LogSize), uints.NewU32(0)})
	}

	// Mix range checks (never mixed)

	// Mix verify bitwise XOR components (same as RC)
}
