package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type JumpDoubleDerefOpcodeClaim struct {
	LogSize uint32
}

type JumpDoubleDerefOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JumpDoubleDerefOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJumpDoubleDerefOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JumpDoubleDerefOpcodeClaim,
	interactionClaim JumpDoubleDerefOpcodeInteractionClaim,
) *JumpDoubleDerefOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &JumpDoubleDerefOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(),
	}
}

func (c *JumpDoubleDerefOpcodeComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	trace := traceSampledValues

	inputPc := trace[0][0]
	inputAp := trace[1][0]
	inputFp := trace[2][0]
	offset1 := trace[3][0]
	offset2 := trace[4][0]
	op0BaseFP := trace[5][0]
	apUpdateAdd1 := trace[6][0]
	mem0Base := trace[7][0]
	mem1BaseID := trace[8][0]
	mem1Limb0 := trace[9][0]
	mem1Limb1 := trace[10][0]
	mem1Limb2 := trace[11][0]
	nextPcID := trace[12][0]
	nextPcLimb0 := trace[13][0]
	nextPcLimb1 := trace[14][0]
	nextPcLimb2 := trace[15][0]
	enabler := trace[16][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstruction9BD86Evaluate(
		c.qm31,
		inputPc,
		offset1,
		offset2,
		op0BaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	// mem0_base relation.
	mem0Expected := c.qm31.Add(
		c.qm31.Mul(op0BaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(c.qm31.One(), op0BaseFP), inputAp),
	)
	constraint = c.qm31.Sub(mem0Base, mem0Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readMem1Base := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem0Base, decoded.Offset1MinusBase),
		mem1BaseID,
		mem1Limb0,
		mem1Limb1,
		mem1Limb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := readMem1Base.AddressLookupSum
	memoryIdToBigSum2 := readMem1Base.IdToBigLookupSum

	mem1Value := c.qm31.Add(
		c.qm31.Add(mem1Limb0, c.qm31.Mul(mem1Limb1, qm31Const(512))),
		c.qm31.Mul(mem1Limb2, qm31Const(262144)),
	)

	readNextPc := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem1Value, decoded.Offset2MinusBase),
		nextPcID,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum3 := readNextPc.AddressLookupSum
	memoryIdToBigSum4 := readNextPc.IdToBigLookupSum

	var err error
	opcodesSum5, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPcValue := c.qm31.Add(
		c.qm31.Add(nextPcLimb0, c.qm31.Mul(nextPcLimb1, qm31Const(512))),
		c.qm31.Mul(nextPcLimb2, qm31Const(262144)),
	)

	opcodesSum6, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			nextPcValue,
			c.qm31.Add(inputAp, apUpdateAdd1),
			inputFp,
		},
	)
	if err != nil {
		panic(err)
	}

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

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifyInstructionSum, memoryAddressSum1))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum2, memoryAddressSum3))
	constraint = c.qm31.Sub(constraint, memoryIdToBigSum2)
	constraint = c.qm31.Sub(constraint, memoryAddressSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memoryIdToBigSum4, opcodesSum5))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum4, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(part3, part2)
	diff3 = c.qm31.Sub(diff3, part3Prev)
	diff3 = c.qm31.Add(diff3, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff3, opcodesSum6), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
