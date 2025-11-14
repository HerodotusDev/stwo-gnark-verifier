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

	addApOpcodes                []*cairo_components.AddApOpcodeComponent
	addModBuiltin               *cairo_components.AddModBuiltinComponent
	addOpcodes                  []*cairo_components.AddOpcodeComponent
	addSmallOpcodes             []*cairo_components.AddSmallOpcodeComponent
	assertEqDoubleDerefOpcodes  []*cairo_components.AssertEqDoubleDerefOpcodeComponent
	assertEqImmOpcodes          []*cairo_components.AssertEqImmOpcodeComponent
	assertEqOpcodes             []*cairo_components.AssertEqOpcodeComponent
	bitwiseBuiltin              *cairo_components.BitwiseBuiltinComponent
	blakeCompressOpcodes        []*cairo_components.BlakeCompressOpcodeComponent
	blakeG                      *cairo_components.BlakeGComponent
	blakeRound                  *cairo_components.BlakeRoundComponent
	blakeRoundSigma             *cairo_components.BlakeRoundSigmaComponent
	callOpcodes                 []*cairo_components.CallOpcodeComponent
	callRelImmOpcodes           []*cairo_components.CallRelImmOpcodeComponent
	cube252                     *cairo_components.Cube252Component
	genericOpcodes              []*cairo_components.GenericOpcodeComponent
	jnzOpcodes                  []*cairo_components.JnzOpcodeComponent
	jnzTakenOpcodes             []*cairo_components.JnzTakenOpcodeComponent
	jumpDoubleDerefOpcodes      []*cairo_components.JumpDoubleDerefOpcodeComponent
	jumpOpcodes                 []*cairo_components.JumpOpcodeComponent
	jumpRelImmOpcodes           []*cairo_components.JumpRelImmOpcodeComponent
	jumpRelOpcodes              []*cairo_components.JumpRelOpcodeComponent
	memoryAddressToId           *cairo_components.MemoryAddressToIdComponent
	memoryIdToBigBigComponents  []*cairo_components.MemoryIdToBigBigComponent
	memoryIdToBigSmallComponent *cairo_components.MemoryIdToBigSmallComponent
	mulModBuiltin               *cairo_components.MulModBuiltinComponent
	mulOpcodes                  []*cairo_components.MulOpcodeComponent
	mulSmallOpcodes             []*cairo_components.MulSmallOpcodeComponent
	partialEcMul                *cairo_components.PartialEcMulComponent
	pedersenBuiltin             *cairo_components.PedersenBuiltinComponent
	pedersenPointsTable         *cairo_components.PedersenPointsTableComponent
	poseidon3PartialRoundsChain *cairo_components.Poseidon3PartialRoundsChainComponent
	poseidonBuiltin             *cairo_components.PoseidonBuiltinComponent
	poseidonFullRoundChain      *cairo_components.PoseidonFullRoundChainComponent
	poseidonRoundKeys           *cairo_components.PoseidonRoundKeysComponent
	qm31Opcodes                 []*cairo_components.Qm31OpcodeComponent
	rangeCheck11                *cairo_components.RangeCheck11Component
	rangeCheck12                *cairo_components.RangeCheck12Component
	rangeCheck18                *cairo_components.RangeCheck18Component
	rangeCheck19                *cairo_components.RangeCheck19Component
	rangeCheck3_3_3_3_3         *cairo_components.RangeCheck3_3_3_3_3Component
	rangeCheck3_6_6_3           *cairo_components.RangeCheck3_6_6_3Component
	rangeCheck4_3               *cairo_components.RangeCheck4_3Component
	rangeCheck4_4_4_4           *cairo_components.RangeCheck4_4_4_4Component
	rangeCheck4_4               *cairo_components.RangeCheck4_4Component
	rangeCheck5_4               *cairo_components.RangeCheck5_4Component
	rangeCheck6                 *cairo_components.RangeCheck6Component
	rangeCheck7_2_5             *cairo_components.RangeCheck7_2_5Component
	rangeCheck8                 *cairo_components.RangeCheck8Component
	rangeCheck9_9               *cairo_components.RangeCheck9_9Component
	rangeCheckBuiltin128        *cairo_components.RangeCheck128BuiltinComponent
	rangeCheckBuiltin96         *cairo_components.RangeCheck96BuiltinComponent
	rangeCheckFelt252Width27    *cairo_components.RangeCheckFelt252Width27Component
	retOpcodes                  []*cairo_components.RetOpcodeComponent
	tripleXor32                 *cairo_components.TripleXor32Component
	verifyBitwiseXor12          *cairo_components.VerifyBitwiseXor12Component
	verifyBitwiseXor4           *cairo_components.VerifyBitwiseXor4Component
	verifyBitwiseXor7           *cairo_components.VerifyBitwiseXor7Component
	verifyBitwiseXor8           *cairo_components.VerifyBitwiseXor8Component
	verifyBitwiseXor9           *cairo_components.VerifyBitwiseXor9Component
	verifyInstruction           *cairo_components.VerifyInstructionComponent
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
) *Components {
	comp := &Components{
		api:    api,
		m31:    m31Chip,
		qm31:   qm31Chip,
		circle: circleChip,
	}
	vanishEvalInverses := make(map[uints.U8]m31.QM31, circle.CircleLogOrder)
	for logSize := uint8(4); logSize < circle.CircleLogOrder; logSize++ {
		vanishEvalInverses[uints.NewU8(logSize)] = circleChip.CanonicVanishingInverse(uint32(logSize), oodsPoint)
	}

	// opcode components
	if claims := claim.Opcodes.AddAp; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.AddAp
		comp.addApOpcodes = make([]*cairo_components.AddApOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.addApOpcodes = append(comp.addApOpcodes, cairo_components.NewAddApOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC1_9,
				cairoInteractionElements.RangeChecks.RC8,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Add; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Add
		comp.addOpcodes = make([]*cairo_components.AddOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.addOpcodes = append(comp.addOpcodes, cairo_components.NewAddOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.AddSmall; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.AddSmall
		comp.addSmallOpcodes = make([]*cairo_components.AddSmallOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.addSmallOpcodes = append(comp.addSmallOpcodes, cairo_components.NewAddSmallOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.AssertEqDoubleDeref; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.AssertEqDoubleDeref
		comp.assertEqDoubleDerefOpcodes = make([]*cairo_components.AssertEqDoubleDerefOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.assertEqDoubleDerefOpcodes = append(comp.assertEqDoubleDerefOpcodes, cairo_components.NewAssertEqDoubleDerefOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.AssertEqImm; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.AssertEqImm
		comp.assertEqImmOpcodes = make([]*cairo_components.AssertEqImmOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.assertEqImmOpcodes = append(comp.assertEqImmOpcodes, cairo_components.NewAssertEqImmOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.AssertEq; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.AssertEq
		comp.assertEqOpcodes = make([]*cairo_components.AssertEqOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.assertEqOpcodes = append(comp.assertEqOpcodes, cairo_components.NewAssertEqOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Blake; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Blake
		comp.blakeCompressOpcodes = make([]*cairo_components.BlakeCompressOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.blakeCompressOpcodes = append(comp.blakeCompressOpcodes, cairo_components.NewBlakeCompressOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC7_2_5,
				cairoInteractionElements.VerifyBitwiseXor8,
				cairoInteractionElements.BlakeRound,
				cairoInteractionElements.TripleXor32,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Call; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Call
		comp.callOpcodes = make([]*cairo_components.CallOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.callOpcodes = append(comp.callOpcodes, cairo_components.NewCallOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.CallRelImm; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.CallRelImm
		comp.callRelImmOpcodes = make([]*cairo_components.CallRelImmOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.callRelImmOpcodes = append(comp.callRelImmOpcodes, cairo_components.NewCallRelImmOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	// Additional opcode components
	if claims := claim.Opcodes.Generic; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Generic
		comp.genericOpcodes = make([]*cairo_components.GenericOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.genericOpcodes = append(comp.genericOpcodes, cairo_components.NewGenericOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC9_9,
				cairoInteractionElements.RangeChecks.RC1_9,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Jnz; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Jnz
		comp.jnzOpcodes = make([]*cairo_components.JnzOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jnzOpcodes = append(comp.jnzOpcodes, cairo_components.NewJnzOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.JnzTaken; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.JnzTaken
		comp.jnzTakenOpcodes = make([]*cairo_components.JnzTakenOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jnzTakenOpcodes = append(comp.jnzTakenOpcodes, cairo_components.NewJnzTakenOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.JumpDoubleDeref; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.JumpDoubleDeref
		comp.jumpDoubleDerefOpcodes = make([]*cairo_components.JumpDoubleDerefOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jumpDoubleDerefOpcodes = append(comp.jumpDoubleDerefOpcodes, cairo_components.NewJumpDoubleDerefOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Jump; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Jump
		comp.jumpOpcodes = make([]*cairo_components.JumpOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jumpOpcodes = append(comp.jumpOpcodes, cairo_components.NewJumpOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.JumpRelImm; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.JumpRelImm
		comp.jumpRelImmOpcodes = make([]*cairo_components.JumpRelImmOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jumpRelImmOpcodes = append(comp.jumpRelImmOpcodes, cairo_components.NewJumpRelImmOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.JumpRel; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.JumpRel
		comp.jumpRelOpcodes = make([]*cairo_components.JumpRelOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.jumpRelOpcodes = append(comp.jumpRelOpcodes, cairo_components.NewJumpRelOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Mul; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Mul
		comp.mulOpcodes = make([]*cairo_components.MulOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.mulOpcodes = append(comp.mulOpcodes, cairo_components.NewMulOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC1_9,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.MulSmall; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.MulSmall
		comp.mulSmallOpcodes = make([]*cairo_components.MulSmallOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.mulSmallOpcodes = append(comp.mulSmallOpcodes, cairo_components.NewMulSmallOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC1_1,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Qm31; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Qm31
		comp.qm31Opcodes = make([]*cairo_components.Qm31OpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.qm31Opcodes = append(comp.qm31Opcodes, cairo_components.NewQm31Opcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC4_4_4_4,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	if claims := claim.Opcodes.Ret; len(claims) > 0 {
		interactions := interactionClaim.Opcodes.Ret
		comp.retOpcodes = make([]*cairo_components.RetOpcodeComponent, 0, len(claims))
		for i, opcodeClaim := range claims {
			comp.retOpcodes = append(comp.retOpcodes, cairo_components.NewRetOpcode(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyInstruction,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.Opcodes,
				vanishEvalInverses[opcodeClaim.LogSize],
				opcodeClaim,
				interactions[i],
			))
		}
	}

	// Builtin components
	if builtin := claim.Builtins.AddModBuiltin; builtin != nil && interactionClaim.Builtins.AddModBuiltin != nil {
		comp.addModBuiltin = cairo_components.NewAddModBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.AddModBuiltin,
		)
	}

	if builtin := claim.Builtins.BitwiseBuiltin; builtin != nil && interactionClaim.Builtins.BitwiseBuiltin != nil {
		comp.bitwiseBuiltin = cairo_components.NewBitwiseBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.VerifyBitwiseXor9,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.BitwiseBuiltin,
		)
	}

	if builtin := claim.Builtins.MulModBuiltin; builtin != nil && interactionClaim.Builtins.MulModBuiltin != nil {
		comp.mulModBuiltin = cairo_components.NewMulModBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC1_2,
			cairoInteractionElements.RangeChecks.RC4_4,
			cairoInteractionElements.RangeChecks.RC1_8,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.MulModBuiltin,
		)
	}

	if builtin := claim.Builtins.PedersenBuiltin; builtin != nil && interactionClaim.Builtins.PedersenBuiltin != nil {
		comp.pedersenBuiltin = cairo_components.NewPedersenBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC5_4,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC8,
			cairoInteractionElements.PartialEcMul,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.PedersenBuiltin,
		)
	}

	if builtin := claim.Builtins.PoseidonBuiltin; builtin != nil && interactionClaim.Builtins.PoseidonBuiltin != nil {
		comp.poseidonBuiltin = cairo_components.NewPoseidonBuiltin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.PoseidonFullRoundChain,
			cairoInteractionElements.RangeCheckFelt252Width27,
			cairoInteractionElements.Cube252,
			cairoInteractionElements.RangeChecks.RC3_3_3_3_3,
			cairoInteractionElements.RangeChecks.RC4_4_4_4,
			cairoInteractionElements.RangeChecks.RC4_4,
			cairoInteractionElements.Poseidon3PartialRoundsChain,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.PoseidonBuiltin,
		)
	}

	if builtin := claim.Builtins.RangeCheck96; builtin != nil && interactionClaim.Builtins.RangeCheck96 != nil {
		comp.rangeCheckBuiltin96 = cairo_components.NewRangeCheck96Builtin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.RangeChecks.RC6,
			cairoInteractionElements.MemoryIDToValue,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.RangeCheck96,
		)
	}

	if builtin := claim.Builtins.RangeCheck128; builtin != nil && interactionClaim.Builtins.RangeCheck128 != nil {
		comp.rangeCheckBuiltin128 = cairo_components.NewRangeCheck128Builtin(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			vanishEvalInverses[builtin.LogSize],
			*builtin,
			*interactionClaim.Builtins.RangeCheck128,
		)
	}

	// Memory ID components
	comp.memoryAddressToId = cairo_components.NewMemoryAddressToId(
		api,
		qm31Chip,
		cairoInteractionElements.MemoryAddressToId,
		claim.MemoryAddressToId,
		interactionClaim.MemoryAddressToId,
		vanishEvalInverses[claim.MemoryAddressToId.LogSize],
	)
	if bigClaims := claim.MemoryIDToValue.Big; len(bigClaims) > 0 {
		claimedSums := interactionClaim.MemoryIDToValue.BigClaimedSums
		comp.memoryIdToBigBigComponents = make([]*cairo_components.MemoryIdToBigBigComponent, 0, len(bigClaims))
		for i, bigClaim := range bigClaims {
			comp.memoryIdToBigBigComponents = append(comp.memoryIdToBigBigComponents, cairo_components.NewMemoryIdToBigBigComponent(
				api,
				qm31Chip,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.RangeChecks.RC9_9,
				vanishEvalInverses[bigClaim.LogSize],
				bigClaim,
				cairo_components.MemoryIdToBigBigInteractionClaim{ClaimedSum: claimedSums[i]},
			))
		}
	}

	if smallClaim := claim.MemoryIDToValue.Small; smallClaim != nil {
		comp.memoryIdToBigSmallComponent = cairo_components.NewMemoryIdToBigSmallComponent(
			api,
			qm31Chip,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.RangeChecks.RC9_9,
			vanishEvalInverses[smallClaim.LogSize],
			*smallClaim,
			cairo_components.MemoryIdToBigSmallInteractionClaim{ClaimedSum: interactionClaim.MemoryIDToValue.SmallClaimedSum},
		)
	}

	// Blake context components
	if blakeClaim := claim.BlakeContext.Claim; blakeClaim != nil && interactionClaim.BlakeContext.InteractionClaim != nil {
		blakeInteraction := interactionClaim.BlakeContext.InteractionClaim
		if blakeClaim.BlakeG != nil {
			comp.blakeG = cairo_components.NewBlakeG(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyBitwiseXor8,
				cairoInteractionElements.VerifyBitwiseXor12,
				cairoInteractionElements.VerifyBitwiseXor4,
				cairoInteractionElements.VerifyBitwiseXor7,
				cairoInteractionElements.VerifyBitwiseXor9,
				cairoInteractionElements.BlakeG,
				vanishEvalInverses[blakeClaim.BlakeG.LogSize],
				*blakeClaim.BlakeG,
				blakeInteraction.BlakeG,
			)
		}
		if blakeClaim.BlakeRound != nil {
			comp.blakeRound = cairo_components.NewBlakeRound(
				api,
				qm31Chip,
				cairoInteractionElements.BlakeRoundSigma,
				cairoInteractionElements.RangeChecks.RC7_2_5,
				cairoInteractionElements.MemoryAddressToId,
				cairoInteractionElements.MemoryIDToValue,
				cairoInteractionElements.BlakeG,
				cairoInteractionElements.BlakeRound,
				vanishEvalInverses[blakeClaim.BlakeRound.LogSize],
				*blakeClaim.BlakeRound,
				blakeInteraction.BlakeRound,
			)
		}
		if blakeClaim.BlakeRoundSigma != nil {
			comp.blakeRoundSigma = cairo_components.NewBlakeRoundSigma(
				qm31Chip,
				cairoInteractionElements.BlakeRoundSigma,
				vanishEvalInverses[uints.NewU8(4)],
				*blakeClaim.BlakeRoundSigma,
				blakeInteraction.BlakeRoundSigma,
			)
		}
		if blakeClaim.TripleXor32 != nil {
			comp.tripleXor32 = cairo_components.NewTripleXor32(
				qm31Chip,
				cairoInteractionElements.VerifyBitwiseXor8,
				cairoInteractionElements.TripleXor32,
				vanishEvalInverses[uints.NewU8(uint8(blakeClaim.TripleXor32.LogSize))],
				*blakeClaim.TripleXor32,
				blakeInteraction.TripleXor32,
			)
		}
		if blakeClaim.VerifyBitwiseXor12 != nil {
			comp.verifyBitwiseXor12 = cairo_components.NewVerifyBitwiseXor12(
				api,
				qm31Chip,
				cairoInteractionElements.VerifyBitwiseXor12,
				vanishEvalInverses[uints.NewU8(20)],
				blakeInteraction.VerifyBitwiseXor12,
			)
		}
	}

	// Pedersen context components
	if pedersenClaim := claim.PedersenContext.Claim; pedersenClaim != nil && interactionClaim.PedersenContext.InteractionClaim != nil {
		pedersenInteraction := interactionClaim.PedersenContext.InteractionClaim
		if pedersenClaim.PartialEcMul != nil {
			comp.partialEcMul = cairo_components.NewPartialEcMul(
				api,
				qm31Chip,
				cairoInteractionElements.PedersenPointsTable,
				cairoInteractionElements.RangeChecks.RC9_9,
				cairoInteractionElements.RangeChecks.RC1_9,
				cairoInteractionElements.PartialEcMul,
				vanishEvalInverses[pedersenClaim.PartialEcMul.LogSize],
				*pedersenClaim.PartialEcMul,
				pedersenInteraction.PartialEcMul,
			)
		}
		if pedersenClaim.PedersenPointsTable != nil {
			comp.pedersenPointsTable = cairo_components.NewPedersenPointsTable(
				api,
				qm31Chip,
				cairoInteractionElements.PedersenPointsTable,
				vanishEvalInverses[uints.NewU8(23)],
				pedersenInteraction.PedersenPointsTable,
			)
		}
	}

	// Poseidon context components
	if poseidonClaim := claim.PoseidonContext.Claim; poseidonClaim != nil && interactionClaim.PoseidonContext.InteractionClaim != nil {
		poseidonInteraction := interactionClaim.PoseidonContext.InteractionClaim
		if poseidonClaim.Poseidon3PartialRoundsChain != nil {
			comp.poseidon3PartialRoundsChain = cairo_components.NewPoseidon3PartialRoundsChain(
				api,
				qm31Chip,
				cairoInteractionElements.PoseidonRoundKeys,
				cairoInteractionElements.Cube252,
				cairoInteractionElements.RangeChecks.RC4_4_4_4,
				cairoInteractionElements.RangeChecks.RC4_4,
				cairoInteractionElements.RangeCheckFelt252Width27,
				cairoInteractionElements.Poseidon3PartialRoundsChain,
				vanishEvalInverses[poseidonClaim.Poseidon3PartialRoundsChain.LogSize],
				*poseidonClaim.Poseidon3PartialRoundsChain,
				poseidonInteraction.Poseidon3PartialRoundsChain,
			)
		}
		if poseidonClaim.PoseidonFullRoundChain != nil {
			comp.poseidonFullRoundChain = cairo_components.NewPoseidonFullRoundChain(
				api,
				qm31Chip,
				cairoInteractionElements.Cube252,
				cairoInteractionElements.PoseidonRoundKeys,
				cairoInteractionElements.RangeChecks.RC3_3_3_3_3,
				cairoInteractionElements.PoseidonFullRoundChain,
				vanishEvalInverses[poseidonClaim.PoseidonFullRoundChain.LogSize],
				*poseidonClaim.PoseidonFullRoundChain,
				poseidonInteraction.PoseidonFullRoundChain,
			)
		}
		if poseidonClaim.Cube252 != nil {
			comp.cube252 = cairo_components.NewCube252(
				api,
				qm31Chip,
				cairoInteractionElements.RangeChecks.RC9_9,
				cairoInteractionElements.RangeChecks.RC1_9,
				cairoInteractionElements.Cube252,
				vanishEvalInverses[poseidonClaim.Cube252.LogSize],
				*poseidonClaim.Cube252,
				poseidonInteraction.Cube252,
			)
		}
		if poseidonClaim.PoseidonRoundKeys != nil {
			comp.poseidonRoundKeys = cairo_components.NewPoseidonRoundKeys(
				qm31Chip,
				cairoInteractionElements.PoseidonRoundKeys,
				vanishEvalInverses[uints.NewU8(6)],
				poseidonInteraction.PoseidonRoundKeys,
			)
		}
		if poseidonClaim.RangeCheckFelt252Width27 != nil {
			comp.rangeCheckFelt252Width27 = cairo_components.NewRangeCheckFelt252Width27(
				api,
				qm31Chip,
				cairoInteractionElements.RangeChecks.RC9_9,
				cairoInteractionElements.RangeChecks.RC1_8,
				cairoInteractionElements.RangeCheckFelt252Width27,
				vanishEvalInverses[poseidonClaim.RangeCheckFelt252Width27.LogSize],
				*poseidonClaim.RangeCheckFelt252Width27,
				poseidonInteraction.RangeCheckFelt252Width27,
			)
		}
	}

	// Range check components
	if claim.RangeChecks.RC6 != nil {
		comp.rangeCheck6 = cairo_components.NewRangeCheck6(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC6,
			vanishEvalInverses[uints.NewU8(6)],
			interactionClaim.RangeChecks.RC6,
		)
	}
	if claim.RangeChecks.RC8 != nil {
		comp.rangeCheck8 = cairo_components.NewRangeCheck8(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC8,
			vanishEvalInverses[uints.NewU8(8)],
			interactionClaim.RangeChecks.RC8,
		)
	}
	if claim.RangeChecks.RC11 != nil {
		comp.rangeCheck11 = cairo_components.NewRangeCheck11(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC1_1,
			vanishEvalInverses[uints.NewU8(11)],
			interactionClaim.RangeChecks.RC11,
		)
	}
	if claim.RangeChecks.RC12 != nil {
		comp.rangeCheck12 = cairo_components.NewRangeCheck12(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC1_2,
			vanishEvalInverses[uints.NewU8(12)],
			interactionClaim.RangeChecks.RC12,
		)
	}
	if claim.RangeChecks.RC18 != nil {
		comp.rangeCheck18 = cairo_components.NewRangeCheck18(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC1_8,
			vanishEvalInverses[uints.NewU8(18)],
			interactionClaim.RangeChecks.RC18,
		)
	}
	if claim.RangeChecks.RC19 != nil {
		comp.rangeCheck19 = cairo_components.NewRangeCheck19(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC1_9,
			vanishEvalInverses[uints.NewU8(19)],
			interactionClaim.RangeChecks.RC19,
		)
	}
	if claim.RangeChecks.RC4_3 != nil {
		comp.rangeCheck4_3 = cairo_components.NewRangeCheck4_3(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC4_3,
			vanishEvalInverses[uints.NewU8(7)],
			interactionClaim.RangeChecks.RC4_3,
		)
	}
	if claim.RangeChecks.RC4_4 != nil {
		comp.rangeCheck4_4 = cairo_components.NewRangeCheck4_4(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC4_4,
			vanishEvalInverses[uints.NewU8(8)],
			interactionClaim.RangeChecks.RC4_4,
		)
	}
	if claim.RangeChecks.RC5_4 != nil {
		comp.rangeCheck5_4 = cairo_components.NewRangeCheck5_4(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC5_4,
			vanishEvalInverses[uints.NewU8(9)],
			interactionClaim.RangeChecks.RC5_4,
		)
	}
	if claim.RangeChecks.RC9_9 != nil {
		comp.rangeCheck9_9 = cairo_components.NewRangeCheck9_9(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC9_9,
			vanishEvalInverses[uints.NewU8(18)],
			interactionClaim.RangeChecks.RC9_9,
		)
	}
	if claim.RangeChecks.RC7_2_5 != nil {
		comp.rangeCheck7_2_5 = cairo_components.NewRangeCheck7_2_5(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC7_2_5,
			vanishEvalInverses[uints.NewU8(14)],
			interactionClaim.RangeChecks.RC7_2_5,
		)
	}
	if claim.RangeChecks.RC3_6_6_3 != nil {
		comp.rangeCheck3_6_6_3 = cairo_components.NewRangeCheck3_6_6_3(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC3_6_6_3,
			vanishEvalInverses[uints.NewU8(18)],
			interactionClaim.RangeChecks.RC3_6_6_3,
		)
	}
	if claim.RangeChecks.RC4_4_4_4 != nil {
		comp.rangeCheck4_4_4_4 = cairo_components.NewRangeCheck4_4_4_4(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC4_4_4_4,
			vanishEvalInverses[uints.NewU8(16)],
			interactionClaim.RangeChecks.RC4_4_4_4,
		)
	}
	if claim.RangeChecks.RC3_3_3_3_3 != nil {
		comp.rangeCheck3_3_3_3_3 = cairo_components.NewRangeCheck3_3_3_3_3(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC3_3_3_3_3,
			vanishEvalInverses[uints.NewU8(15)],
			interactionClaim.RangeChecks.RC3_3_3_3_3,
		)
	}

	// Verify bitwise xor components
	comp.verifyBitwiseXor4 = cairo_components.NewVerifyBitwiseXor4(
		api,
		qm31Chip,
		cairoInteractionElements.VerifyBitwiseXor4,
		vanishEvalInverses[uints.NewU8(8)],
		cairo_components.VerifyBitwiseXor4InteractionClaim{ClaimedSum: interactionClaim.VerifyBitwiseXor4.ClaimedSum},
	)
	comp.verifyBitwiseXor7 = cairo_components.NewVerifyBitwiseXor7(
		api,
		qm31Chip,
		cairoInteractionElements.VerifyBitwiseXor7,
		vanishEvalInverses[uints.NewU8(14)],
		cairo_components.VerifyBitwiseXor7InteractionClaim{ClaimedSum: interactionClaim.VerifyBitwiseXor7.ClaimedSum},
	)
	comp.verifyBitwiseXor8 = cairo_components.NewVerifyBitwiseXor8(
		api,
		qm31Chip,
		cairoInteractionElements.VerifyBitwiseXor8,
		vanishEvalInverses[uints.NewU8(16)],
		cairo_components.VerifyBitwiseXor8InteractionClaim{ClaimedSum: interactionClaim.VerifyBitwiseXor8.ClaimedSum},
	)
	comp.verifyBitwiseXor9 = cairo_components.NewVerifyBitwiseXor9(
		api,
		qm31Chip,
		cairoInteractionElements.VerifyBitwiseXor9,
		vanishEvalInverses[uints.NewU8(18)],
		cairo_components.VerifyBitwiseXor9InteractionClaim{ClaimedSum: interactionClaim.VerifyBitwiseXor9.ClaimedSum},
	)

	// Verify instruction
	if claim.VerifyInstruction != nil {
		comp.verifyInstruction = cairo_components.NewVerifyInstruction(
			api,
			qm31Chip,
			cairoInteractionElements.RangeChecks.RC7_2_5,
			cairoInteractionElements.RangeChecks.RC4_3,
			cairoInteractionElements.MemoryAddressToId,
			cairoInteractionElements.MemoryIDToValue,
			cairoInteractionElements.VerifyInstruction,
			vanishEvalInverses[claim.VerifyInstruction.LogSize],
			*claim.VerifyInstruction,
			interactionClaim.VerifyInstruction,
		)
	}

	return comp
}

func (c *Components) Evaluate(sampledValues [][][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	// Prepare sampled values
	preprocessedSampledValuesRaw := sampledValues[cairo_components.PREPROCESSED_IDX]
	preprocessedSampledValues := cairo_components.NewPreprocessedSampledValues(c.api, c.m31, preprocessedSampledValuesRaw)
	traceSampledValues := sampledValues[cairo_components.MAIN_IDX]
	interactionSampledValues := sampledValues[cairo_components.INTERACTION_IDX]

	traces := cairo_components.NewTraces(preprocessedSampledValues, traceSampledValues, interactionSampledValues)

	// Evaluate components
	sum := c.qm31.Zero()
	// Opcode components
	for _, comp := range c.addOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.addSmallOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.addApOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.assertEqOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.assertEqImmOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.assertEqDoubleDerefOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.blakeCompressOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.callOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.callRelImmOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.genericOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jnzOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jnzTakenOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jumpOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jumpDoubleDerefOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jumpRelOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.jumpRelImmOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.mulOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.mulSmallOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.qm31Opcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	for _, comp := range c.retOpcodes {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}

	// Verify instruction
	if c.verifyInstruction != nil {
		sum = c.verifyInstruction.Evaluate(sum, traces, random_coeff)
	}

	// Blake context
	if c.blakeRound != nil {
		sum = c.blakeRound.Evaluate(sum, traces, random_coeff)
	}
	if c.blakeG != nil {
		sum = c.blakeG.Evaluate(sum, traces, random_coeff)
	}
	if c.blakeRoundSigma != nil {
		sum = c.blakeRoundSigma.Evaluate(sum, traces, random_coeff)
	}
	if c.tripleXor32 != nil {
		sum = c.tripleXor32.Evaluate(sum, traces, random_coeff)
	}
	if c.verifyBitwiseXor12 != nil {
		sum = c.verifyBitwiseXor12.Evaluate(sum, traces, random_coeff)
	}

	// Builtin components
	if c.addModBuiltin != nil {
		sum = c.addModBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if c.bitwiseBuiltin != nil {
		sum = c.bitwiseBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if c.mulModBuiltin != nil {
		sum = c.mulModBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if c.pedersenBuiltin != nil {
		sum = c.pedersenBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if c.poseidonBuiltin != nil {
		sum = c.poseidonBuiltin.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheckBuiltin96 != nil {
		sum = c.rangeCheckBuiltin96.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheckBuiltin128 != nil {
		sum = c.rangeCheckBuiltin128.Evaluate(sum, traces, random_coeff)
	}

	// Pedersen context
	if c.partialEcMul != nil {
		sum = c.partialEcMul.Evaluate(sum, traces, random_coeff)
	}
	if c.pedersenPointsTable != nil {
		sum = c.pedersenPointsTable.Evaluate(sum, traces, random_coeff)
	}
	// Poseidon context
	if c.poseidon3PartialRoundsChain != nil {
		sum = c.poseidon3PartialRoundsChain.Evaluate(sum, traces, random_coeff)
	}
	if c.poseidonFullRoundChain != nil {
		sum = c.poseidonFullRoundChain.Evaluate(sum, traces, random_coeff)
	}
	if c.cube252 != nil {
		sum = c.cube252.Evaluate(sum, traces, random_coeff)
	}
	if c.poseidonRoundKeys != nil {
		sum = c.poseidonRoundKeys.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheckFelt252Width27 != nil {
		sum = c.rangeCheckFelt252Width27.Evaluate(sum, traces, random_coeff)
	}

	// Memory Address to ID
	if c.memoryAddressToId != nil {
		sum = c.memoryAddressToId.Evaluate(sum, traces, random_coeff)
	}
	// Memory ID lookups
	for _, comp := range c.memoryIdToBigBigComponents {
		sum = comp.Evaluate(sum, traces, random_coeff)
	}
	if c.memoryIdToBigSmallComponent != nil {
		sum = c.memoryIdToBigSmallComponent.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck6 != nil {
		sum = c.rangeCheck6.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck8 != nil {
		sum = c.rangeCheck8.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck11 != nil {
		sum = c.rangeCheck11.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck12 != nil {
		sum = c.rangeCheck12.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck18 != nil {
		sum = c.rangeCheck18.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck19 != nil {
		sum = c.rangeCheck19.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck4_3 != nil {
		sum = c.rangeCheck4_3.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck4_4 != nil {
		sum = c.rangeCheck4_4.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck5_4 != nil {
		sum = c.rangeCheck5_4.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck9_9 != nil {
		sum = c.rangeCheck9_9.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck7_2_5 != nil {
		sum = c.rangeCheck7_2_5.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck3_6_6_3 != nil {
		sum = c.rangeCheck3_6_6_3.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck4_4_4_4 != nil {
		sum = c.rangeCheck4_4_4_4.Evaluate(sum, traces, random_coeff)
	}
	if c.rangeCheck3_3_3_3_3 != nil {
		sum = c.rangeCheck3_3_3_3_3.Evaluate(sum, traces, random_coeff)
	}

	// Verify bitwise XOR lookups
	if c.verifyBitwiseXor4 != nil {
		sum = c.verifyBitwiseXor4.Evaluate(sum, traces, random_coeff)
	}
	if c.verifyBitwiseXor7 != nil {
		sum = c.verifyBitwiseXor7.Evaluate(sum, traces, random_coeff)
	}
	if c.verifyBitwiseXor8 != nil {
		sum = c.verifyBitwiseXor8.Evaluate(sum, traces, random_coeff)
	}
	if c.verifyBitwiseXor9 != nil {
		sum = c.verifyBitwiseXor9.Evaluate(sum, traces, random_coeff)
	}
	return sum
}
