package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type CallRelImmOpcodeClaim struct {
	LogSize uint32
}

type CallRelImmOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type CallRelImmOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewCallRelImmOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim CallRelImmOpcodeClaim,
	interactionClaim CallRelImmOpcodeInteractionClaim,
) *CallRelImmOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &CallRelImmOpcodeComponent{
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

func (c *CallRelImmOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(18, 20)

	trace := traceSampledValues

	inputPc := trace[0][0]
	inputAp := trace[1][0]
	inputFp := trace[2][0]
	storedFpID := trace[3][0]
	storedFpLimb0 := trace[4][0]
	storedFpLimb1 := trace[5][0]
	storedFpLimb2 := trace[6][0]
	storedRetPcID := trace[7][0]
	storedRetPcLimb0 := trace[8][0]
	storedRetPcLimb1 := trace[9][0]
	storedRetPcLimb2 := trace[10][0]
	distanceID := trace[11][0]
	msb := trace[12][0]
	midLimbsSet := trace[13][0]
	distanceLimb0 := trace[14][0]
	distanceLimb1 := trace[15][0]
	distanceLimb2 := trace[16][0]
	enabler := trace[17][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	verifyInstructionSum := sub.DecodeInstruction2A7A2Evaluate(
		c.qm31,
		inputPc,
		c.verifyInstructionElements,
	)

	readStoredFp := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		inputAp,
		storedFpID,
		storedFpLimb0,
		storedFpLimb1,
		storedFpLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := readStoredFp.AddressLookupSum
	memoryIdToBigSum2 := readStoredFp.IdToBigLookupSum

	storedFpValue := c.qm31.Add(
		c.qm31.Add(
			storedFpLimb0,
			c.qm31.Mul(storedFpLimb1, qm31Const(512)),
		),
		c.qm31.Mul(storedFpLimb2, qm31Const(262144)),
	)
	constraint = c.qm31.Sub(storedFpValue, inputFp)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readStoredRet := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(inputAp, c.qm31.One()),
		storedRetPcID,
		storedRetPcLimb0,
		storedRetPcLimb1,
		storedRetPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum3 := readStoredRet.AddressLookupSum
	memoryIdToBigSum4 := readStoredRet.IdToBigLookupSum

	storedRetValue := c.qm31.Add(
		c.qm31.Add(
			storedRetPcLimb0,
			c.qm31.Mul(storedRetPcLimb1, qm31Const(512)),
		),
		c.qm31.Mul(storedRetPcLimb2, qm31Const(262144)),
	)
	constraint = c.qm31.Sub(storedRetValue, c.qm31.Add(inputPc, qm31Const(2)))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readDistance := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(inputPc, c.qm31.One()),
		distanceID,
		msb,
		midLimbsSet,
		distanceLimb0,
		distanceLimb1,
		distanceLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressSum5 := readDistance.AddressLookupSum
	memoryIdToBigSum6 := readDistance.IdToBigLookupSum
	sum = readDistance.Sum

	var err error
	opcodesSum7, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, readDistance.Value)
	nextApPlusTwo := c.qm31.Add(inputAp, qm31Const(2))

	opcodesSum8, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{nextPc, nextApPlusTwo, nextApPlusTwo},
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
		interactionSampledValues[12][0],
		interactionSampledValues[13][0],
		interactionSampledValues[14][0],
		interactionSampledValues[15][0],
	)
	part4 := c.qm31.FromPartialEvals(
		interactionSampledValues[16][1],
		interactionSampledValues[17][1],
		interactionSampledValues[18][1],
		interactionSampledValues[19][1],
	)
	part4Prev := c.qm31.FromPartialEvals(
		interactionSampledValues[16][0],
		interactionSampledValues[17][0],
		interactionSampledValues[18][0],
		interactionSampledValues[19][0],
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
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memoryIdToBigSum4, memoryAddressSum5))
	constraint = c.qm31.Sub(constraint, memoryIdToBigSum4)
	constraint = c.qm31.Sub(constraint, memoryAddressSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff3, c.qm31.Mul(memoryIdToBigSum6, opcodesSum7))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum6, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff4 := c.qm31.Sub(part4, part3)
	diff4 = c.qm31.Sub(diff4, part4Prev)
	diff4 = c.qm31.Add(diff4, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff4, opcodesSum8), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
