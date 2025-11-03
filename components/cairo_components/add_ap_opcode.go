package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type AddApOpcodeClaim struct {
	LogSize uint32
}

type AddApOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type AddApOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck19Elements      m31.InteractionElements
	rangeCheck8Elements       m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewAddApOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	rangeCheck8Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim AddApOpcodeClaim,
	interactionClaim AddApOpcodeInteractionClaim,
) *AddApOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	return &AddApOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck19Elements:      rangeCheck19Elements,
		rangeCheck8Elements:       rangeCheck8Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(), // TODO: compute actual value from evaluation point.
	}
}

func (c *AddApOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(15, 16)

	inputPc := traceSampledValues[0][0]
	inputAp := traceSampledValues[1][0]
	inputFp := traceSampledValues[2][0]
	offset2 := traceSampledValues[3][0]
	op1Imm := traceSampledValues[4][0]
	op1BaseFp := traceSampledValues[5][0]
	mem1Base := traceSampledValues[6][0]
	op1Id := traceSampledValues[7][0]
	msb := traceSampledValues[8][0]
	midLimbsSet := traceSampledValues[9][0]
	op1Limb0 := traceSampledValues[10][0]
	op1Limb1 := traceSampledValues[11][0]
	op1Limb2 := traceSampledValues[12][0]
	nextApBot8Bits := traceSampledValues[13][0]
	enabler := traceSampledValues[14][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstructionD2A10Evaluate(
		c.qm31,
		inputPc,
		offset2,
		op1Imm,
		op1BaseFp,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	// Constraint - if imm then offset2 is 1.
	constraint = c.qm31.Mul(
		op1Imm,
		c.qm31.Sub(c.qm31.One(), decoded.Offset2MinusBase),
	)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint - mem1_base relation.
	mem1BaseExpected := c.qm31.Add(
		c.qm31.Add(
			c.qm31.Mul(op1Imm, inputPc),
			c.qm31.Mul(op1BaseFp, inputFp),
		),
		c.qm31.Mul(decoded.Op1BaseAP, inputAp),
	)
	constraint = c.qm31.Sub(mem1Base, mem1BaseExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readSmall := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		op1Id,
		msb,
		midLimbsSet,
		op1Limb0,
		op1Limb1,
		op1Limb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressToIdSum := readSmall.AddressLookupSum
	memoryIdToBigSum := readSmall.IdToBigLookupSum
	sum = readSmall.Sum

	nextAp := c.qm31.Add(inputAp, readSmall.Value)

	var err error
	rangeCheck19Sum, err := c.qm31.Combine(
		c.rangeCheck19Elements,
		[]m31.QM31{
			c.qm31.Mul(
				c.qm31.Sub(nextAp, nextApBot8Bits),
				qm31Const(8388608),
			),
		},
	)
	if err != nil {
		panic(err)
	}

	rangeCheck8Sum, err := c.qm31.Combine(
		c.rangeCheck8Elements,
		[]m31.QM31{nextApBot8Bits},
	)
	if err != nil {
		panic(err)
	}

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
			c.qm31.Add(inputPc, c.qm31.Add(c.qm31.One(), op1Imm)),
			nextAp,
			inputFp,
		},
	)
	if err != nil {
		panic(err)
	}

	// Lookup constraints.
	part0 := c.qm31.FromPartialEvals(
		interactionSampledValues[0][0],
		interactionSampledValues[1][0],
		interactionSampledValues[2][0],
		interactionSampledValues[3][0],
	)
	part1 := c.qm31.FromPartialEvals(
		interactionSampledValues[4][0],
		interactionSampledValues[5][0],
		interactionSampledValues[6][0],
		interactionSampledValues[7][0],
	)
	part2 := c.qm31.FromPartialEvals(
		interactionSampledValues[8][0],
		interactionSampledValues[9][0],
		interactionSampledValues[10][0],
		interactionSampledValues[11][0],
	)
	part3 := c.qm31.FromPartialEvals(
		interactionSampledValues[12][1],
		interactionSampledValues[13][1],
		interactionSampledValues[14][1],
		interactionSampledValues[15][1],
	)
	part3Prev := c.qm31.FromPartialEvals(
		interactionSampledValues[12][0],
		interactionSampledValues[13][0],
		interactionSampledValues[14][0],
		interactionSampledValues[15][0],
	)

	constraint = c.qm31.Mul(
		part0,
		c.qm31.Mul(verifyInstructionSum, memoryAddressToIdSum),
	)
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressToIdSum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum, rangeCheck19Sum))
	constraint = c.qm31.Sub(constraint, memoryIdToBigSum)
	constraint = c.qm31.Sub(constraint, rangeCheck19Sum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(rangeCheck8Sum, opcodesSum0))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(rangeCheck8Sum, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum0)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(part3, part2)
	diff3 = c.qm31.Sub(diff3, part3Prev)
	diff3 = c.qm31.Add(diff3, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff3, opcodesSum1), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
