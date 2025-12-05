package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// A chip for OODS
type Components struct {
	api    frontend.API
	m31    *m31.M31Chip
	qm31   *m31.QM31Chip
	circle *circle.CircleChip

	addApOpcodes                cairo_components.AddApOpcodeComponent
	addModBuiltin               cairo_components.AddModBuiltinComponent
	addOpcodes                  cairo_components.AddOpcodeComponent
	addSmallOpcodes             cairo_components.AddSmallOpcodeComponent
	assertEqDoubleDerefOpcodes  cairo_components.AssertEqDoubleDerefOpcodeComponent
	assertEqImmOpcodes          cairo_components.AssertEqImmOpcodeComponent
	assertEqOpcodes             cairo_components.AssertEqOpcodeComponent
	bitwiseBuiltin              cairo_components.BitwiseBuiltinComponent
	blakeCompressOpcodes        cairo_components.BlakeCompressOpcodeComponent
	blakeG                      cairo_components.BlakeGComponent
	blakeRound                  cairo_components.BlakeRoundComponent
	blakeRoundSigma             cairo_components.BlakeRoundSigmaComponent
	callOpcodes                 cairo_components.CallOpcodeComponent
	callRelImmOpcodes           cairo_components.CallRelImmOpcodeComponent
	cube252                     cairo_components.Cube252Component
	genericOpcodes              cairo_components.GenericOpcodeComponent
	jnzOpcodes                  cairo_components.JnzOpcodeComponent
	jnzTakenOpcodes             cairo_components.JnzTakenOpcodeComponent
	jumpDoubleDerefOpcodes      cairo_components.JumpDoubleDerefOpcodeComponent
	jumpOpcodes                 cairo_components.JumpOpcodeComponent
	jumpRelImmOpcodes           cairo_components.JumpRelImmOpcodeComponent
	jumpRelOpcodes              cairo_components.JumpRelOpcodeComponent
	memoryAddressToId           cairo_components.MemoryAddressToIDComponent
	memoryIdToBigBigComponents  cairo_components.MemoryIdToBigBigComponent
	memoryIdToBigSmallComponent cairo_components.MemoryIdToBigSmallComponent
	mulModBuiltin               cairo_components.MulModBuiltinComponent
	mulOpcodes                  cairo_components.MulOpcodeComponent
	mulSmallOpcodes             cairo_components.MulSmallOpcodeComponent
	partialEcMul                cairo_components.PartialEcMulComponent
	pedersenBuiltin             cairo_components.PedersenBuiltinComponent
	pedersenPointsTable         cairo_components.PedersenPointsTableComponent
	poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainComponent
	poseidonBuiltin             cairo_components.PoseidonBuiltinComponent
	poseidonFullRoundChain      cairo_components.PoseidonFullRoundChainComponent
	poseidonRoundKeys           cairo_components.PoseidonRoundKeysComponent
	qm31Opcodes                 cairo_components.Qm31OpcodeComponent
	rangeCheck11                cairo_components.RangeCheck11Component
	rangeCheck12                cairo_components.RangeCheck12Component
	rangeCheck18                cairo_components.RangeCheck18Component
	rangeCheck19                cairo_components.RangeCheck19Component
	rangeCheck33333             cairo_components.RangeCheck33333Component
	rangeCheck3663              cairo_components.RangeCheck3663Component
	rangeCheck43                cairo_components.RangeCheck43Component
	rangeCheck4444              cairo_components.RangeCheck4444Component
	rangeCheck44                cairo_components.RangeCheck44Component
	rangeCheck54                cairo_components.RangeCheck54Component
	rangeCheck6                 cairo_components.RangeCheck6Component
	rangeCheck725               cairo_components.RangeCheck725Component
	rangeCheck8                 cairo_components.RangeCheck8Component
	rangeCheck99                cairo_components.RangeCheck99Component
	rangeCheckBuiltin128        cairo_components.RangeCheck128BuiltinComponent
	rangeCheckBuiltin96         cairo_components.RangeCheck96BuiltinComponent
	rangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27Component
	retOpcodes                  cairo_components.RetOpcodeComponent
	tripleXor32                 cairo_components.TripleXor32Component
	verifyBitwiseXor12          cairo_components.VerifyBitwiseXor12Component
	verifyBitwiseXor4           cairo_components.VerifyBitwiseXor4Component
	verifyBitwiseXor7           cairo_components.VerifyBitwiseXor7Component
	verifyBitwiseXor8           cairo_components.VerifyBitwiseXor8Component
	verifyBitwiseXor9           cairo_components.VerifyBitwiseXor9Component
	verifyInstruction           cairo_components.VerifyInstructionComponent
}

// Creates a new OODS chip
func NewComponents(
	api frontend.API,
	m31Chip *m31.M31Chip,
	qm31Chip *m31.QM31Chip,
	circleChip *circle.CircleChip,
	cairoInteractionElements variables.CairoInteractionElements,
	claim variables.CairoClaim,
	interactionClaim variables.CairoInteractionClaim,
	oodsPoint circle.Point,
	circuitData variables.CircuitData,
) *Components {
	comp := &Components{
		api:    api,
		m31:    m31Chip,
		qm31:   qm31Chip,
		circle: circleChip,
	}

	// opcode components
	if circuitData.ComponentConfig[0] {
		comp.addApOpcodes = cairo_components.NewAddApOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC19,
			cairoInteractionElements.RangeChecks.RC8,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.AddAp.LogSize, oodsPoint),
			claim.AddAp,
			interactionClaim.AddAp,
		)
	}

	if circuitData.ComponentConfig[1] {
		comp.addOpcodes = cairo_components.NewAddOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Add.LogSize, oodsPoint),
			claim.Add,
			interactionClaim.Add,
		)
	}

	if circuitData.ComponentConfig[2] {
		comp.addSmallOpcodes = cairo_components.NewAddSmallOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.AddSmall.LogSize, oodsPoint),
			claim.AddSmall,
			interactionClaim.AddSmall,
		)
	}

	if circuitData.ComponentConfig[3] {
		comp.assertEqDoubleDerefOpcodes = cairo_components.NewAssertEqDoubleDerefOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.AssertEqDoubleDeref.LogSize, oodsPoint),
			claim.AssertEqDoubleDeref,
			interactionClaim.AssertEqDoubleDeref,
		)
	}

	if circuitData.ComponentConfig[4] {
		comp.assertEqImmOpcodes = cairo_components.NewAssertEqImmOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.AssertEqImm.LogSize, oodsPoint),
			claim.AssertEqImm,
			interactionClaim.AssertEqImm,
		)
	}

	if circuitData.ComponentConfig[5] {
		comp.assertEqOpcodes = cairo_components.NewAssertEqOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.AssertEq.LogSize, oodsPoint),
			claim.AssertEq,
			interactionClaim.AssertEq,
		)
	}

	if circuitData.ComponentConfig[6] {
		comp.blakeCompressOpcodes = cairo_components.NewBlakeCompressOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC725,
			cairoInteractionElements.VerifyBitwiseXor8,
			cairoInteractionElements.BlakeRound,
			cairoInteractionElements.TripleXor32,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Blake.LogSize, oodsPoint),
			claim.Blake,
			interactionClaim.Blake,
		)
	}

	if circuitData.ComponentConfig[7] {
		comp.callOpcodes = cairo_components.NewCallOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Call.LogSize, oodsPoint),
			claim.Call,
			interactionClaim.Call,
		)
	}

	if circuitData.ComponentConfig[8] {
		comp.callRelImmOpcodes = cairo_components.NewCallRelImmOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.CallRelImm.LogSize, oodsPoint),
			claim.CallRelImm,
			interactionClaim.CallRelImm,
		)
	}

	if circuitData.ComponentConfig[9] {
		comp.genericOpcodes = cairo_components.NewGenericOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC99,
			cairoInteractionElements.RangeChecks.RC19,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Generic.LogSize, oodsPoint),
			claim.Generic,
			interactionClaim.Generic,
		)
	}

	if circuitData.ComponentConfig[10] {
		comp.jnzOpcodes = cairo_components.NewJnzOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Jnz.LogSize, oodsPoint),
			claim.Jnz,
			interactionClaim.Jnz,
		)
	}

	if circuitData.ComponentConfig[11] {
		comp.jnzTakenOpcodes = cairo_components.NewJnzTakenOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.JnzTaken.LogSize, oodsPoint),
			claim.JnzTaken,
			interactionClaim.JnzTaken,
		)
	}

	if circuitData.ComponentConfig[12] {
		comp.jumpDoubleDerefOpcodes = cairo_components.NewJumpDoubleDerefOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.JumpDoubleDeref.LogSize, oodsPoint),
			claim.JumpDoubleDeref,
			interactionClaim.JumpDoubleDeref,
		)
	}

	if circuitData.ComponentConfig[13] {
		comp.jumpOpcodes = cairo_components.NewJumpOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Jump.LogSize, oodsPoint),
			claim.Jump,
			interactionClaim.Jump,
		)
	}

	if circuitData.ComponentConfig[14] {
		comp.jumpRelImmOpcodes = cairo_components.NewJumpRelImmOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.JumpRelImm.LogSize, oodsPoint),
			claim.JumpRelImm,
			interactionClaim.JumpRelImm,
		)
	}

	if circuitData.ComponentConfig[15] {
		comp.jumpRelOpcodes = cairo_components.NewJumpRelOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.JumpRel.LogSize, oodsPoint),
			claim.JumpRel,
			interactionClaim.JumpRel,
		)
	}

	if circuitData.ComponentConfig[16] {
		comp.mulOpcodes = cairo_components.NewMulOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC19,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Mul.LogSize, oodsPoint),
			claim.Mul,
			interactionClaim.Mul,
		)
	}

	if circuitData.ComponentConfig[17] {
		comp.mulSmallOpcodes = cairo_components.NewMulSmallOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC11,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.MulSmall.LogSize, oodsPoint),
			claim.MulSmall,
			interactionClaim.MulSmall,
		)
	}

	if circuitData.ComponentConfig[18] {
		comp.qm31Opcodes = cairo_components.NewQm31Opcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC4444,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Qm31.LogSize, oodsPoint),
			claim.Qm31,
			interactionClaim.Qm31,
		)
	}

	if circuitData.ComponentConfig[19] {
		comp.retOpcodes = cairo_components.NewRetOpcode(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyInstruction,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.Opcodes,
			circleChip.CanonicVanishingInverse(claim.Ret.LogSize, oodsPoint),
			claim.Ret,
			interactionClaim.Ret,
		)
	}

	// Builtin components
	if circuitData.ComponentConfig[20] {
		comp.addModBuiltin = cairo_components.NewAddModBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			circleChip.CanonicVanishingInverse(claim.AddModBuiltin.LogSize, oodsPoint),
			claim.AddModBuiltin,
			interactionClaim.AddModBuiltin,
		)
	}

	if circuitData.ComponentConfig[21] {
		comp.bitwiseBuiltin = cairo_components.NewBitwiseBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.VerifyBitwiseXor9,
			circleChip.CanonicVanishingInverse(claim.BitwiseBuiltin.LogSize, oodsPoint),
			claim.BitwiseBuiltin,
			interactionClaim.BitwiseBuiltin,
		)
	}

	if circuitData.ComponentConfig[22] {
		comp.mulModBuiltin = cairo_components.NewMulModBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC12,
			cairoInteractionElements.RangeChecks.RC44,
			cairoInteractionElements.RangeChecks.RC18,
			circleChip.CanonicVanishingInverse(claim.MulModBuiltin.LogSize, oodsPoint),
			claim.MulModBuiltin,
			interactionClaim.MulModBuiltin,
		)
	}

	if circuitData.ComponentConfig[23] {
		comp.pedersenBuiltin = cairo_components.NewPedersenBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC54,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC8,
			cairoInteractionElements.PartialEcMul,
			circleChip.CanonicVanishingInverse(claim.PedersenBuiltin.LogSize, oodsPoint),
			claim.PedersenBuiltin,
			interactionClaim.PedersenBuiltin,
		)
	}

	if circuitData.ComponentConfig[24] {
		comp.poseidonBuiltin = cairo_components.NewPoseidonBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.PoseidonFullRoundChain,
			cairoInteractionElements.RangeCheckFelt252Width27,
			cairoInteractionElements.Cube252,
			cairoInteractionElements.RangeChecks.RC33333,
			cairoInteractionElements.RangeChecks.RC4444,
			cairoInteractionElements.RangeChecks.RC44,
			cairoInteractionElements.Poseidon3PartialRoundsChain,
			circleChip.CanonicVanishingInverse(claim.PoseidonBuiltin.LogSize, oodsPoint),
			claim.PoseidonBuiltin,
			interactionClaim.PoseidonBuiltin,
		)
	}

	if circuitData.ComponentConfig[25] {
		comp.rangeCheckBuiltin96 = cairo_components.NewRangeCheck96Builtin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.RangeChecks.RC6,
			cairoInteractionElements.MemoryIDToValue,
			circleChip.CanonicVanishingInverse(claim.RangeCheck96.LogSize, oodsPoint),
			claim.RangeCheck96,
			interactionClaim.RangeCheck96,
		)
	}

	if circuitData.ComponentConfig[26] {
		comp.rangeCheckBuiltin128 = cairo_components.NewRangeCheck128Builtin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			circleChip.CanonicVanishingInverse(claim.RangeCheck128.LogSize, oodsPoint),
			claim.RangeCheck128,
			interactionClaim.RangeCheck128,
		)
	}

	// Memory ID components
	if circuitData.ComponentConfig[27] {
		comp.memoryAddressToId = cairo_components.NewMemoryAddressToId(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToID,
			claim.MemoryAddressToID,
			interactionClaim.MemoryAddressToID,
			circleChip.CanonicVanishingInverse(claim.MemoryAddressToID.LogSize, oodsPoint),
		)
	}
	if circuitData.ComponentConfig[28] {
		comp.memoryIdToBigBigComponents = cairo_components.NewMemoryIdToBigBigComponent(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC99,
			circleChip.CanonicVanishingInverse(claim.MemoryIDToBigBig.LogSize, oodsPoint),
			claim.MemoryIDToBigBig,
			interactionClaim.MemoryIDToBigBig,
		)
	}

	if circuitData.ComponentConfig[29] {
		comp.memoryIdToBigSmallComponent = cairo_components.NewMemoryIdToBigSmallComponent(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC99,
			circleChip.CanonicVanishingInverse(claim.MemoryIDToBigSmall.LogSize, oodsPoint),
			claim.MemoryIDToBigSmall,
			interactionClaim.MemoryIDToBigSmall,
		)
	}

	// Blake context components
	if circuitData.ComponentConfig[30] {
		comp.blakeG = cairo_components.NewBlakeG(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor8,
			cairoInteractionElements.VerifyBitwiseXor12,
			cairoInteractionElements.VerifyBitwiseXor4,
			cairoInteractionElements.VerifyBitwiseXor7,
			cairoInteractionElements.VerifyBitwiseXor9,
			cairoInteractionElements.BlakeG,
			circleChip.CanonicVanishingInverse(claim.BlakeG.LogSize, oodsPoint),
			claim.BlakeG,
			interactionClaim.BlakeG,
		)
	}
	if circuitData.ComponentConfig[31] {
		comp.blakeRound = cairo_components.NewBlakeRound(
			api,
			qm31Chip,
			cairoInteractionElements.BlakeRoundSigma,
			cairoInteractionElements.RangeChecks.RC725,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.BlakeG,
			cairoInteractionElements.BlakeRound,
			circleChip.CanonicVanishingInverse(claim.BlakeRound.LogSize, oodsPoint),
			claim.BlakeRound,
			interactionClaim.BlakeRound,
		)
	}
	if circuitData.ComponentConfig[32] {
		comp.blakeRoundSigma = cairo_components.NewBlakeRoundSigma(
			api,
			qm31Chip,
			cairoInteractionElements.BlakeRoundSigma,
			circleChip.CanonicVanishingInverse(uints.NewU32(4), oodsPoint),
			claim.BlakeRoundSigma,
			interactionClaim.BlakeRoundSigma,
		)
	}
	if circuitData.ComponentConfig[33] {
		comp.tripleXor32 = cairo_components.NewTripleXor32(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor8,
			cairoInteractionElements.TripleXor32,
			circleChip.CanonicVanishingInverse(claim.TripleXor32.LogSize, oodsPoint),
			claim.TripleXor32,
			interactionClaim.TripleXor32,
		)
	}
	if circuitData.ComponentConfig[34] {
		comp.verifyBitwiseXor12 = cairo_components.NewVerifyBitwiseXor12(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor12,
			circleChip.CanonicVanishingInverse(uints.NewU32(20), oodsPoint),
			interactionClaim.VerifyBitwiseXor12,
		)
	}

	// Pedersen context components
	if circuitData.ComponentConfig[35] {
		comp.partialEcMul = cairo_components.NewPartialEcMul(
			api,
			qm31Chip,
			cairoInteractionElements.PedersenPointsTable,
			cairoInteractionElements.RangeChecks.RC99,
			cairoInteractionElements.RangeChecks.RC19,
			cairoInteractionElements.PartialEcMul,
			circleChip.CanonicVanishingInverse(claim.PartialEcMul.LogSize, oodsPoint),
			claim.PartialEcMul,
			interactionClaim.PartialEcMul,
		)
	}
	if circuitData.ComponentConfig[36] {
		comp.pedersenPointsTable = cairo_components.NewPedersenPointsTable(
			api,
			qm31Chip,
			cairoInteractionElements.PedersenPointsTable,
			circleChip.CanonicVanishingInverse(uints.NewU32(23), oodsPoint),
			interactionClaim.PedersenPointsTable,
		)
	}

	// Poseidon context components
	if circuitData.ComponentConfig[37] {
		comp.poseidon3PartialRoundsChain = cairo_components.NewPoseidon3PartialRoundsChain(
			api,
			qm31Chip,
			cairoInteractionElements.PoseidonRoundKeys,
			cairoInteractionElements.Cube252,
			cairoInteractionElements.RangeChecks.RC4444,
			cairoInteractionElements.RangeChecks.RC44,
			cairoInteractionElements.RangeCheckFelt252Width27,
			cairoInteractionElements.Poseidon3PartialRoundsChain,
			circleChip.CanonicVanishingInverse(claim.Poseidon3PartialRoundsChain.LogSize, oodsPoint),
			claim.Poseidon3PartialRoundsChain,
			interactionClaim.Poseidon3PartialRoundsChain,
		)
	}
	if circuitData.ComponentConfig[38] {
		comp.poseidonFullRoundChain = cairo_components.NewPoseidonFullRoundChain(
			api,
			qm31Chip,
			cairoInteractionElements.Cube252,
			cairoInteractionElements.PoseidonRoundKeys,
			cairoInteractionElements.RangeChecks.RC33333,
			cairoInteractionElements.PoseidonFullRoundChain,
			circleChip.CanonicVanishingInverse(claim.PoseidonFullRoundChain.LogSize, oodsPoint),
			claim.PoseidonFullRoundChain,
			interactionClaim.PoseidonFullRoundChain,
		)
	}
	if circuitData.ComponentConfig[39] {
		comp.cube252 = cairo_components.NewCube252(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC99,
			cairoInteractionElements.RangeChecks.RC19,
			cairoInteractionElements.Cube252,
			circleChip.CanonicVanishingInverse(claim.Cube252.LogSize, oodsPoint),
			claim.Cube252,
			interactionClaim.Cube252,
		)
	}
	if circuitData.ComponentConfig[40] {
		comp.poseidonRoundKeys = cairo_components.NewPoseidonRoundKeys(
			api,
			qm31Chip,
			cairoInteractionElements.PoseidonRoundKeys,
			circleChip.CanonicVanishingInverse(uints.NewU32(6), oodsPoint),
			interactionClaim.PoseidonRoundKeys,
		)
	}
	if circuitData.ComponentConfig[41] {
		comp.rangeCheckFelt252Width27 = cairo_components.NewRangeCheckFelt252Width27(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC99,
			cairoInteractionElements.RangeChecks.RC18,
			cairoInteractionElements.RangeCheckFelt252Width27,
			circleChip.CanonicVanishingInverse(claim.RangeCheckFelt252Width27.LogSize, oodsPoint),
			claim.RangeCheckFelt252Width27,
			interactionClaim.RangeCheckFelt252Width27,
		)
	}

	// Range check components
	if circuitData.ComponentConfig[42] {
		comp.rangeCheck6 = cairo_components.NewRangeCheck6(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC6,
			circleChip.CanonicVanishingInverse(uints.NewU32(6), oodsPoint),
			interactionClaim.RC6,
		)
	}
	if circuitData.ComponentConfig[43] {
		comp.rangeCheck8 = cairo_components.NewRangeCheck8(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC8,
			circleChip.CanonicVanishingInverse(uints.NewU32(8), oodsPoint),
			interactionClaim.RC8,
		)
	}
	if circuitData.ComponentConfig[44] {
		comp.rangeCheck11 = cairo_components.NewRangeCheck11(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC11,
			circleChip.CanonicVanishingInverse(uints.NewU32(11), oodsPoint),
			interactionClaim.RC11,
		)
	}
	if circuitData.ComponentConfig[45] {
		comp.rangeCheck12 = cairo_components.NewRangeCheck12(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC12,
			circleChip.CanonicVanishingInverse(uints.NewU32(12), oodsPoint),
			interactionClaim.RC12,
		)
	}
	if circuitData.ComponentConfig[46] {
		comp.rangeCheck18 = cairo_components.NewRangeCheck18(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC18,
			circleChip.CanonicVanishingInverse(uints.NewU32(18), oodsPoint),
			interactionClaim.RC18,
		)
	}
	if circuitData.ComponentConfig[47] {
		comp.rangeCheck19 = cairo_components.NewRangeCheck19(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC19,
			circleChip.CanonicVanishingInverse(uints.NewU32(19), oodsPoint),
			interactionClaim.RC19,
		)
	}
	if circuitData.ComponentConfig[48] {
		comp.rangeCheck43 = cairo_components.NewRangeCheck43(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC43,
			circleChip.CanonicVanishingInverse(uints.NewU32(7), oodsPoint),
			interactionClaim.RC43,
		)
	}
	if circuitData.ComponentConfig[49] {
		comp.rangeCheck44 = cairo_components.NewRangeCheck44(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC44,
			circleChip.CanonicVanishingInverse(uints.NewU32(8), oodsPoint),
			interactionClaim.RC44,
		)
	}
	if circuitData.ComponentConfig[50] {
		comp.rangeCheck54 = cairo_components.NewRangeCheck54(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC54,
			circleChip.CanonicVanishingInverse(uints.NewU32(9), oodsPoint),
			interactionClaim.RC54,
		)
	}
	if circuitData.ComponentConfig[51] {
		comp.rangeCheck99 = cairo_components.NewRangeCheck99(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC99,
			circleChip.CanonicVanishingInverse(uints.NewU32(18), oodsPoint),
			interactionClaim.RC99,
		)
	}
	if circuitData.ComponentConfig[52] {
		comp.rangeCheck725 = cairo_components.NewRangeCheck725(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC725,
			circleChip.CanonicVanishingInverse(uints.NewU32(14), oodsPoint),
			interactionClaim.RC725,
		)
	}
	if circuitData.ComponentConfig[53] {
		comp.rangeCheck3663 = cairo_components.NewRangeCheck3663(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC3663,
			circleChip.CanonicVanishingInverse(uints.NewU32(18), oodsPoint),
			interactionClaim.RC3663,
		)
	}
	if circuitData.ComponentConfig[54] {
		comp.rangeCheck4444 = cairo_components.NewRangeCheck4444(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC4444,
			circleChip.CanonicVanishingInverse(uints.NewU32(16), oodsPoint),
			interactionClaim.RC4444,
		)
	}
	if circuitData.ComponentConfig[55] {
		comp.rangeCheck33333 = cairo_components.NewRangeCheck33333(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC33333,
			circleChip.CanonicVanishingInverse(uints.NewU32(15), oodsPoint),
			interactionClaim.RC33333,
		)
	}

	// Verify bitwise xor components
	if circuitData.ComponentConfig[56] {
		comp.verifyBitwiseXor4 = cairo_components.NewVerifyBitwiseXor4(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor4,
			circleChip.CanonicVanishingInverse(uints.NewU32(8), oodsPoint),
			interactionClaim.VerifyBitwiseXor4,
		)
	}
	if circuitData.ComponentConfig[57] {
		comp.verifyBitwiseXor7 = cairo_components.NewVerifyBitwiseXor7(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor7,
			circleChip.CanonicVanishingInverse(uints.NewU32(14), oodsPoint),
			interactionClaim.VerifyBitwiseXor7,
		)
	}
	if circuitData.ComponentConfig[58] {
		comp.verifyBitwiseXor8 = cairo_components.NewVerifyBitwiseXor8(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor8,
			circleChip.CanonicVanishingInverse(uints.NewU32(16), oodsPoint),
			interactionClaim.VerifyBitwiseXor8,
		)
	}
	if circuitData.ComponentConfig[59] {
		comp.verifyBitwiseXor9 = cairo_components.NewVerifyBitwiseXor9(
			api,
			qm31Chip,
			cairoInteractionElements.VerifyBitwiseXor9,
			circleChip.CanonicVanishingInverse(uints.NewU32(18), oodsPoint),
			interactionClaim.VerifyBitwiseXor9,
		)
	}

	// Verify instruction
	if circuitData.ComponentConfig[60] {
		comp.verifyInstruction = cairo_components.NewVerifyInstruction(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC725,
			cairoInteractionElements.RangeChecks.RC43,
			cairoInteractionElements.MemoryAddressToID,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.VerifyInstruction,
			circleChip.CanonicVanishingInverse(claim.VerifyInstruction.LogSize, oodsPoint),
			claim.VerifyInstruction,
			interactionClaim.VerifyInstruction,
		)
	}

	return comp
}

func (c Components) Evaluate(sampledValues [][][]m31.QM31, random_coeff m31.QM31, circuitData variables.CircuitData) m31.QM31 {
	// Prepare sampled values
	preprocessedSampledValuesRaw := sampledValues[cairo_components.PREPROCESSED_IDX]
	preprocessedSampledValues := cairo_components.NewPreprocessedSampledValues(c.api, c.m31, preprocessedSampledValuesRaw)
	traceSampledValues := sampledValues[cairo_components.MAIN_IDX]
	interactionSampledValues := sampledValues[cairo_components.INTERACTION_IDX]

	traces := cairo_components.NewTraces(preprocessedSampledValues, traceSampledValues, interactionSampledValues)

	// Evaluate components
	sum := c.qm31.Zero()

	// Opcode components
	if circuitData.ComponentConfig[0] {
		sum = c.addOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[1] {
		sum = c.addSmallOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[2] {
		sum = c.addApOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[3] {
		sum = c.assertEqOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[4] {
		sum = c.assertEqImmOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[5] {
		sum = c.assertEqDoubleDerefOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[6] {
		sum = c.blakeCompressOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[7] {
		sum = c.callOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[8] {
		sum = c.callRelImmOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[9] {
		sum = c.genericOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[10] {
		sum = c.jnzOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[11] {
		sum = c.jnzTakenOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[12] {
		sum = c.jumpOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[13] {
		sum = c.jumpDoubleDerefOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[14] {
		sum = c.jumpRelOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[15] {
		sum = c.jumpRelImmOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[16] {
		sum = c.mulOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[17] {
		sum = c.mulSmallOpcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[18] {
		sum = c.qm31Opcodes.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[19] {
		sum = c.retOpcodes.Evaluate(sum, traces, random_coeff)
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		sum = c.verifyInstruction.Evaluate(sum, traces, random_coeff)
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		sum = c.blakeRound.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[22] {
		sum = c.blakeG.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[23] {
		sum = c.blakeRoundSigma.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[24] {
		sum = c.tripleXor32.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[25] {
		sum = c.verifyBitwiseXor12.Evaluate(sum, traces, random_coeff)
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		sum = c.addModBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[27] {
		sum = c.bitwiseBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[28] {
		sum = c.mulModBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[29] {
		sum = c.pedersenBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[30] {
		sum = c.poseidonBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[31] {
		sum = c.rangeCheckBuiltin96.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[32] {
		sum = c.rangeCheckBuiltin128.Evaluate(sum, traces, random_coeff)
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		sum = c.partialEcMul.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[34] {
		sum = c.pedersenPointsTable.Evaluate(sum, traces, random_coeff)
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		sum = c.poseidon3PartialRoundsChain.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[36] {
		sum = c.poseidonFullRoundChain.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[37] {
		sum = c.cube252.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[38] {
		sum = c.poseidonRoundKeys.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[39] {
		sum = c.rangeCheckFelt252Width27.Evaluate(sum, traces, random_coeff)
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		sum = c.memoryAddressToId.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[41] {
		sum = c.memoryIdToBigBigComponents.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[42] {
		sum = c.memoryIdToBigSmallComponent.Evaluate(sum, traces, random_coeff)
	}

	// Range check components
	if circuitData.ComponentConfig[43] {
		sum = c.rangeCheck6.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[44] {
		sum = c.rangeCheck8.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[45] {
		sum = c.rangeCheck11.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[46] {
		sum = c.rangeCheck12.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[47] {
		sum = c.rangeCheck18.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[48] {
		sum = c.rangeCheck19.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[49] {
		sum = c.rangeCheck43.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[50] {
		sum = c.rangeCheck44.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[51] {
		sum = c.rangeCheck54.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[52] {
		sum = c.rangeCheck99.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[53] {
		sum = c.rangeCheck725.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[54] {
		sum = c.rangeCheck3663.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[55] {
		sum = c.rangeCheck4444.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[56] {
		sum = c.rangeCheck33333.Evaluate(sum, traces, random_coeff)
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		sum = c.verifyBitwiseXor4.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[58] {
		sum = c.verifyBitwiseXor7.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[59] {
		sum = c.verifyBitwiseXor8.Evaluate(sum, traces, random_coeff)
	}
	if circuitData.ComponentConfig[60] {
		sum = c.verifyBitwiseXor9.Evaluate(sum, traces, random_coeff)
	}
	return sum
}
