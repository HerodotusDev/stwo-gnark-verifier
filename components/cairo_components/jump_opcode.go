package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type JumpOpcodeClaim struct {
	LogSize uint32
}

type JumpOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JumpOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJumpOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JumpOpcodeClaim,
	interactionClaim JumpOpcodeInteractionClaim,
) *JumpOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &JumpOpcodeComponent{
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

func (c *JumpOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(13, 12)

	trace := traceSampledValues

	inputPc := trace[0][0]
	inputAp := trace[1][0]
	inputFp := trace[2][0]
	offset2 := trace[3][0]
	op1BaseFP := trace[4][0]
	op1BaseAP := trace[5][0]
	apUpdateAdd1 := trace[6][0]
	mem1Base := trace[7][0]
	nextPcID := trace[8][0]
	nextPcLimb0 := trace[9][0]
	nextPcLimb1 := trace[10][0]
	nextPcLimb2 := trace[11][0]
	enabler := trace[12][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstruction43E1CEvaluate(
		c.qm31,
		inputPc,
		offset2,
		op1BaseFP,
		op1BaseAP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	// op1_base_fp + op1_base_ap = 1.
	constraint = c.qm31.Sub(c.qm31.Add(op1BaseFP, op1BaseAP), c.qm31.One())
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem1_base relation.
	mem1Expected := c.qm31.Add(
		c.qm31.Mul(op1BaseFP, inputFp),
		c.qm31.Mul(op1BaseAP, inputAp),
	)
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readNextPc := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		nextPcID,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := readNextPc.AddressLookupSum
	memoryIdToBigSum2 := readNextPc.IdToBigLookupSum

	var err error
	opcodesSum3, err := c.qm31.Combine(
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

	opcodesSum4, err := c.qm31.Combine(
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
		interactionSampledValues[8][1],
		interactionSampledValues[9][1],
		interactionSampledValues[10][1],
		interactionSampledValues[11][1],
	)
	part2Prev := c.qm31.FromPartialEvals(
		interactionSampledValues[8][0],
		interactionSampledValues[9][0],
		interactionSampledValues[10][0],
		interactionSampledValues[11][0],
	)

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifyInstructionSum, memoryAddressSum1))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum2, opcodesSum3))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum2, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(part2, part1)
	diff2 = c.qm31.Sub(diff2, part2Prev)
	diff2 = c.qm31.Add(diff2, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff2, opcodesSum4), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
