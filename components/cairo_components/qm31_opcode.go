package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type Qm31OpcodeClaim struct {
	LogSize uint32
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
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck4444Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim Qm31OpcodeClaim,
	interactionClaim Qm31OpcodeInteractionClaim,
) *Qm31OpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(uint64(columnSize)))
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	return &Qm31OpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck4444Elements:    rangeCheck4444Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(),
	}
}

func (c *Qm31OpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(73, 24)

	trace := traceSampledValues

	get := func(idx int) m31.QM31 {
		return trace[idx][0]
	}

	inputPc := get(0)
	inputAp := get(1)
	inputFp := get(2)
	offset0 := get(3)
	offset1 := get(4)
	offset2 := get(5)
	dstBaseFP := get(6)
	op0BaseFP := get(7)
	op1Imm := get(8)
	op1BaseFP := get(9)
	resAdd := get(10)
	apUpdateAdd1 := get(11)
	memDstBase := get(12)
	mem0Base := get(13)
	mem1Base := get(14)
	dstID := get(15)
	dstLimbs := gatherLimbs(trace, 16, 16)
	dstDeltaABInv := get(32)
	dstDeltaCDInv := get(33)
	op0ID := get(34)
	op0Limbs := gatherLimbs(trace, 35, 16)
	op0DeltaABInv := get(51)
	op0DeltaCDInv := get(52)
	op1ID := get(53)
	op1Limbs := gatherLimbs(trace, 54, 16)
	op1DeltaABInv := get(70)
	op1DeltaCDInv := get(71)
	enabler := get(72)

	// Enabler must be boolean.
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

	sum = qm31OpcodeLookupConstraints(
		c.qm31,
		sum,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		c.columnSizeInv,
		enabler,
		interactionSampledValues,
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

func qm31OpcodeLookupConstraints(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	columnSizeInv m31.QM31,
	enabler m31.QM31,
	interactionSampledValues [][]m31.QM31,
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
	if len(interactionSampledValues) != 24 {
		panic("qm31 opcode interaction columns mismatch")
	}

	trace := make([]m31.QM31, 24)
	var prevTail [4]m31.QM31

	for i, column := range interactionSampledValues {
		switch {
		case i >= 20:
			if len(column) != 2 {
				panic("qm31 opcode tail interaction column missing prev sample")
			}
			prevTail[i-20] = column[0]
			trace[i] = column[1]
		case len(column) == 1:
			trace[i] = column[0]
		default:
			panic("qm31 opcode interaction column missing value")
		}
	}

	partials := make([]m31.QM31, 6)
	for i := 0; i < 6; i++ {
		base := i * 4
		partials[i] = qm31.FromPartialEvals(
			trace[base],
			trace[base+1],
			trace[base+2],
			trace[base+3],
		)
	}

	prevPartial := qm31.FromPartialEvals(
		prevTail[0],
		prevTail[1],
		prevTail[2],
		prevTail[3],
	)

	// Lookup constraint 0.
	constraint := qm31.Mul(
		partials[0],
		qm31.Mul(verifyInstructionSum, memAddrSumDst),
	)
	constraint = qm31.Sub(constraint, verifyInstructionSum)
	constraint = qm31.Sub(constraint, memAddrSumDst)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Lookup constraint 1.
	diff := qm31.Sub(partials[1], partials[0])
	constraint = qm31.Mul(diff, qm31.Mul(memIdSumDst, rangeCheckDst))
	constraint = qm31.Sub(constraint, memIdSumDst)
	constraint = qm31.Sub(constraint, rangeCheckDst)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Lookup constraint 2.
	diff = qm31.Sub(partials[2], partials[1])
	constraint = qm31.Mul(diff, qm31.Mul(memAddrSumOp0, memIdSumOp0))
	constraint = qm31.Sub(constraint, memAddrSumOp0)
	constraint = qm31.Sub(constraint, memIdSumOp0)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Lookup constraint 3.
	diff = qm31.Sub(partials[3], partials[2])
	constraint = qm31.Mul(diff, qm31.Mul(rangeCheckOp0, memAddrSumOp1))
	constraint = qm31.Sub(constraint, rangeCheckOp0)
	constraint = qm31.Sub(constraint, memAddrSumOp1)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Lookup constraint 4.
	diff = qm31.Sub(partials[4], partials[3])
	constraint = qm31.Mul(diff, qm31.Mul(memIdSumOp1, rangeCheckOp1))
	constraint = qm31.Sub(constraint, memIdSumOp1)
	constraint = qm31.Sub(constraint, rangeCheckOp1)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Lookup constraint 5.
	diff = qm31.Sub(partials[5], partials[4])
	diff = qm31.Sub(diff, prevPartial)
	diff = qm31.Add(diff, qm31.Mul(claimedSum, columnSizeInv))
	constraint = qm31.Mul(diff, qm31.Mul(opcodesSum0, opcodesSum1))
	constraint = qm31.Add(constraint, qm31.Mul(opcodesSum0, enabler))
	constraint = qm31.Sub(constraint, qm31.Mul(opcodesSum1, enabler))
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
