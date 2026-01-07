package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	Qm31OpcodeTraceColumns       = 73
	Qm31OpcodeInteractionColumns = 24
)

type Qm31OpcodeClaim struct {
	LogSize frontend.Variable
}

type Qm31OpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type Qm31OpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck4444Elements    m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewQm31Opcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck4444Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim Qm31OpcodeClaim,
	interactionClaim Qm31OpcodeInteractionClaim,
) Qm31OpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return Qm31OpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck4444Elements:    rangeCheck4444Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c Qm31OpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(Qm31OpcodeTraceColumns, Qm31OpcodeInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputPc := traceSampledValues.Get(0)
	inputAp := traceSampledValues.Get(1)
	inputFp := traceSampledValues.Get(2)
	offset0 := traceSampledValues.Get(3)
	offset1 := traceSampledValues.Get(4)
	offset2 := traceSampledValues.Get(5)
	dstBaseFP := traceSampledValues.Get(6)
	op0BaseFP := traceSampledValues.Get(7)
	op1Imm := traceSampledValues.Get(8)
	op1BaseFP := traceSampledValues.Get(9)
	resAdd := traceSampledValues.Get(10)
	apUpdateAdd1 := traceSampledValues.Get(11)
	memDstBase := traceSampledValues.Get(12)
	mem0Base := traceSampledValues.Get(13)
	mem1Base := traceSampledValues.Get(14)
	dstID := traceSampledValues.Get(15)
	dstLimbs := traceSampledValues.Slice(16, 16)
	dstDeltaABInv := traceSampledValues.Get(32)
	dstDeltaCDInv := traceSampledValues.Get(33)
	op0ID := traceSampledValues.Get(34)
	op0Limbs := traceSampledValues.Slice(35, 16)
	op0DeltaABInv := traceSampledValues.Get(51)
	op0DeltaCDInv := traceSampledValues.Get(52)
	op1ID := traceSampledValues.Get(53)
	op1Limbs := traceSampledValues.Slice(54, 16)
	op1DeltaABInv := traceSampledValues.Get(70)
	op1DeltaCDInv := traceSampledValues.Get(71)
	enabler := traceSampledValues.Get(72)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 6)
	for i := 0; i < 5; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	partials[5] = interactionSampledValues.Partial(c.qm31, 20, 1)
	prevPartial := interactionSampledValues.Partial(c.qm31, 20, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decode := sub.DecodeInstruction3802DEvaluate(
		c.qm31,
		inputPc,
		offset0,
		offset1,
		offset2,
		dstBaseFP,
		op0BaseFP,
		op1Imm,
		op1BaseFP,
		resAdd,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifySum := decode.VerifySum
	sum = decode.Sum

	// If op1 is immediate its offset must equal one.
	constraint = c.qm31.Mul(
		op1Imm,
		c.qm31.Sub(decode.Offset2MinusBase, c.qm31.One()),
	)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	one := c.qm31.One()

	// mem_dst_base relation.
	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(one, dstBaseFP), inputAp),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem0_base relation.
	mem0Expected := c.qm31.Add(
		c.qm31.Mul(op0BaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(one, op0BaseFP), inputAp),
	)
	constraint = c.qm31.Sub(mem0Base, mem0Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem1_base relation.
	mem1Expected := c.qm31.Add(
		c.qm31.Add(
			c.qm31.Mul(op1BaseFP, inputFp),
			c.qm31.Mul(decode.Op1BaseAP, inputAp),
		),
		c.qm31.Mul(op1Imm, inputPc),
	)
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	dstRead := sub.Qm31ReadReducedEvaluate(
		c.qm31,
		c.qm31.Add(memDstBase, decode.Offset0MinusBase),
		dstID,
		dstLimbs,
		dstDeltaABInv,
		dstDeltaCDInv,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.rangeCheck4444Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = dstRead.Sum

	op0Read := sub.Qm31ReadReducedEvaluate(
		c.qm31,
		c.qm31.Add(mem0Base, decode.Offset1MinusBase),
		op0ID,
		op0Limbs,
		op0DeltaABInv,
		op0DeltaCDInv,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.rangeCheck4444Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = op0Read.Sum

	op1Read := sub.Qm31ReadReducedEvaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decode.Offset2MinusBase),
		op1ID,
		op1Limbs,
		op1DeltaABInv,
		op1DeltaCDInv,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.rangeCheck4444Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = op1Read.Sum

	dstReduced := dstRead.ReducedLimbs
	op0Reduced := op0Read.ReducedLimbs
	op1Reduced := op1Read.ReducedLimbs

	resMul := decode.ResAddInactive

	two := qm31Const(2)

	// First component.
	mulTerm := c.qm31.Sub(
		c.qm31.Add(
			c.qm31.Sub(
				c.qm31.Mul(op0Reduced[0], op1Reduced[0]),
				c.qm31.Mul(op0Reduced[1], op1Reduced[1]),
			),
			c.qm31.Mul(
				two,
				c.qm31.Sub(
					c.qm31.Mul(op0Reduced[2], op1Reduced[2]),
					c.qm31.Mul(op0Reduced[3], op1Reduced[3]),
				),
			),
		),
		c.qm31.Add(
			c.qm31.Mul(op0Reduced[2], op1Reduced[3]),
			c.qm31.Mul(op0Reduced[3], op1Reduced[2]),
		),
	)
	expected := c.qm31.Add(
		c.qm31.Mul(mulTerm, resMul),
		c.qm31.Mul(c.qm31.Add(op0Reduced[0], op1Reduced[0]), resAdd),
	)
	constraint = c.qm31.Sub(dstReduced[0], expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Second component.
	mulTerm = c.qm31.Sub(
		c.qm31.Add(
			c.qm31.Add(
				c.qm31.Add(
					c.qm31.Mul(op0Reduced[0], op1Reduced[1]),
					c.qm31.Mul(op0Reduced[1], op1Reduced[0]),
				),
				c.qm31.Mul(
					two,
					c.qm31.Add(
						c.qm31.Mul(op0Reduced[2], op1Reduced[3]),
						c.qm31.Mul(op0Reduced[3], op1Reduced[2]),
					),
				),
			),
			c.qm31.Mul(op0Reduced[2], op1Reduced[2]),
		),
		c.qm31.Mul(op0Reduced[3], op1Reduced[3]),
	)
	expected = c.qm31.Add(
		c.qm31.Mul(mulTerm, resMul),
		c.qm31.Mul(c.qm31.Add(op0Reduced[1], op1Reduced[1]), resAdd),
	)
	constraint = c.qm31.Sub(dstReduced[1], expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Third component.
	mulTerm = c.qm31.Sub(
		c.qm31.Add(
			c.qm31.Sub(
				c.qm31.Mul(op0Reduced[0], op1Reduced[2]),
				c.qm31.Mul(op0Reduced[1], op1Reduced[3]),
			),
			c.qm31.Mul(op0Reduced[2], op1Reduced[0]),
		),
		c.qm31.Mul(op0Reduced[3], op1Reduced[1]),
	)
	expected = c.qm31.Add(
		c.qm31.Mul(mulTerm, resMul),
		c.qm31.Mul(c.qm31.Add(op0Reduced[2], op1Reduced[2]), resAdd),
	)
	constraint = c.qm31.Sub(dstReduced[2], expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Fourth component.
	mulTerm = c.qm31.Add(
		c.qm31.Add(
			c.qm31.Mul(op0Reduced[0], op1Reduced[3]),
			c.qm31.Mul(op0Reduced[1], op1Reduced[2]),
		),
		c.qm31.Add(
			c.qm31.Mul(op0Reduced[2], op1Reduced[1]),
			c.qm31.Mul(op0Reduced[3], op1Reduced[0]),
		),
	)
	expected = c.qm31.Add(
		c.qm31.Mul(mulTerm, resMul),
		c.qm31.Mul(c.qm31.Add(op0Reduced[3], op1Reduced[3]), resAdd),
	)
	constraint = c.qm31.Sub(dstReduced[3], expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	opcodesSum0, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	opcodesSum1, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			c.qm31.Add(c.qm31.Add(inputPc, one), op1Imm),
			c.qm31.Add(inputAp, apUpdateAdd1),
			inputFp,
		},
	)
	if err != nil {
		panic(err)
	}

	sum = c.qm31OpcodeLookupConstraints(
		sum,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		c.columnSizeInv,
		enabler,
		partials,
		prevPartial,
		verifySum,
		dstRead.AddressLookupSum,
		dstRead.IdToBigLookupSum,
		dstRead.RangeCheckSum,
		op0Read.AddressLookupSum,
		op0Read.IdToBigLookupSum,
		op0Read.RangeCheckSum,
		op1Read.AddressLookupSum,
		op1Read.IdToBigLookupSum,
		op1Read.RangeCheckSum,
		opcodesSum0,
		opcodesSum1,
	)

	return sum
}

func (c *Qm31OpcodeComponent) qm31OpcodeLookupConstraints(
	sum m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	columnSizeInv m31.QM31,
	enabler m31.QM31,
	partials []m31.QM31,
	prevPartial m31.QM31,
	verifyInstructionSum m31.QM31,
	memAddrSumDst m31.QM31,
	memIdSumDst m31.QM31,
	rangeCheckDst m31.QM31,
	memAddrSumOp0 m31.QM31,
	memIdSumOp0 m31.QM31,
	rangeCheckOp0 m31.QM31,
	memAddrSumOp1 m31.QM31,
	memIdSumOp1 m31.QM31,
	rangeCheckOp1 m31.QM31,
	opcodesSum0 m31.QM31,
	opcodesSum1 m31.QM31,
) m31.QM31 {
	// Lookup constraint 0.
	constraint := c.qm31.Mul(
		partials[0],
		c.qm31.Mul(verifyInstructionSum, memAddrSumDst),
	)
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memAddrSumDst)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Lookup constraint 1.
	diff := c.qm31.Sub(partials[1], partials[0])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdSumDst, rangeCheckDst))
	constraint = c.qm31.Sub(constraint, memIdSumDst)
	constraint = c.qm31.Sub(constraint, rangeCheckDst)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Lookup constraint 2.
	diff = c.qm31.Sub(partials[2], partials[1])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memAddrSumOp0, memIdSumOp0))
	constraint = c.qm31.Sub(constraint, memAddrSumOp0)
	constraint = c.qm31.Sub(constraint, memIdSumOp0)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Lookup constraint 3.
	diff = c.qm31.Sub(partials[3], partials[2])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(rangeCheckOp0, memAddrSumOp1))
	constraint = c.qm31.Sub(constraint, rangeCheckOp0)
	constraint = c.qm31.Sub(constraint, memAddrSumOp1)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Lookup constraint 4.
	diff = c.qm31.Sub(partials[4], partials[3])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdSumOp1, rangeCheckOp1))
	constraint = c.qm31.Sub(constraint, memIdSumOp1)
	constraint = c.qm31.Sub(constraint, rangeCheckOp1)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Lookup constraint 5.
	diff = c.qm31.Sub(partials[5], partials[4])
	diff = c.qm31.Sub(diff, prevPartial)
	diff = c.qm31.Add(diff, c.qm31.Mul(claimedSum, columnSizeInv))
	constraint = c.qm31.Mul(diff, c.qm31.Mul(opcodesSum0, opcodesSum1))
	constraint = c.qm31.Add(constraint, c.qm31.Mul(opcodesSum0, enabler))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(opcodesSum1, enabler))
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
