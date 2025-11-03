package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type JumpRelImmOpcodeClaim struct {
	LogSize uint32
}

type JumpRelImmOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JumpRelImmOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJumpRelImmOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JumpRelImmOpcodeClaim,
	interactionClaim JumpRelImmOpcodeInteractionClaim,
) *JumpRelImmOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &JumpRelImmOpcodeComponent{
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

func (c *JumpRelImmOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(11, 12)

	trace := traceSampledValues

	inputPc := trace[0][0]
	inputAp := trace[1][0]
	inputFp := trace[2][0]
	apUpdateAdd1 := trace[3][0]
	nextPcID := trace[4][0]
	msb := trace[5][0]
	midLimbsSet := trace[6][0]
	nextPcLimb0 := trace[7][0]
	nextPcLimb1 := trace[8][0]
	nextPcLimb2 := trace[9][0]
	enabler := trace[10][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	verifyInstructionSum, sum := sub.DecodeInstruction7EBC4Evaluate(
		c.qm31,
		inputPc,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	readNextPc := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(inputPc, c.qm31.One()),
		nextPcID,
		msb,
		midLimbsSet,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressSum1 := readNextPc.AddressLookupSum
	memoryIdToBigSum2 := readNextPc.IdToBigLookupSum
	sum = readNextPc.Sum

	var err error
	opcodesSum3, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, readNextPc.Value)

	opcodesSum4, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			nextPc,
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
