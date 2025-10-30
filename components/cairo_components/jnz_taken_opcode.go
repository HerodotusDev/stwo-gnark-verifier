package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type JnzTakenOpcodeClaim struct {
	LogSize uint32
}

type JnzTakenOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JnzTakenOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJnzTakenOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JnzTakenOpcodeClaim,
	interactionClaim JnzTakenOpcodeInteractionClaim,
) *JnzTakenOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &JnzTakenOpcodeComponent{
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

func (c *JnzTakenOpcodeComponent) Evaluate(
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
	offset0 := trace[3][0]
	dstBaseFP := trace[4][0]
	apUpdateAdd1 := trace[5][0]
	memDstBase := trace[6][0]
	dstID := trace[7][0]
	dstLimbs := gatherLimbs(trace, 8, 28)
	res := trace[36][0]
	resSquares := trace[37][0]
	nextPcID := trace[38][0]
	nextPcMSB := trace[39][0]
	nextPcMidSet := trace[40][0]
	nextPcLimb0 := trace[41][0]
	nextPcLimb1 := trace[42][0]
	nextPcLimb2 := trace[43][0]
	enabler := trace[44][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstructionDE75AEvaluate(
		c.qm31,
		inputPc,
		offset0,
		dstBaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum
	offset0MinusBase := decoded.Offset0MinusBase

	one := c.qm31.One()

	// mem_dst_base relation.
	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(one, dstBaseFP), inputAp),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	dstLookup := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(memDstBase, offset0MinusBase),
		dstID,
		dstLimbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := dstLookup.AddressLookupSum
	memoryIdToBigSum2 := dstLookup.IdToBigLookupSum

	// dst != 0 by enforcing inverse.
	sumLimbs := dstLimbs[0]
	for i := 1; i < len(dstLimbs); i++ {
		sumLimbs = c.qm31.Add(sumLimbs, dstLimbs[i])
	}
	constraint = c.qm31.Sub(c.qm31.Mul(sumLimbs, res), one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff0 := c.qm31.Sub(dstLimbs[0], one)
	diff21 := c.qm31.Sub(dstLimbs[21], qm31Const(136))
	diff27 := c.qm31.Sub(dstLimbs[27], qm31Const(256))

	sumSquares := c.qm31.Mul(diff0, diff0)
	for i := 1; i <= 20; i++ {
		sumSquares = c.qm31.Add(sumSquares, dstLimbs[i])
	}
	sumSquares = c.qm31.Add(sumSquares, c.qm31.Mul(diff21, diff21))
	for i := 22; i <= 26; i++ {
		sumSquares = c.qm31.Add(sumSquares, dstLimbs[i])
	}
	sumSquares = c.qm31.Add(sumSquares, c.qm31.Mul(diff27, diff27))

	constraint = c.qm31.Sub(c.qm31.Mul(sumSquares, resSquares), one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readSmall := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(inputPc, one),
		nextPcID,
		nextPcMSB,
		nextPcMidSet,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressSum3 := readSmall.AddressLookupSum
	memoryIdToBigSum4 := readSmall.IdToBigLookupSum
	sum = readSmall.Sum
	nextPcValue := readSmall.Value

	opcodesSum5, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, nextPcValue)
	nextAp := c.qm31.Add(inputAp, apUpdateAdd1)

	opcodesSum6, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{nextPc, nextAp, inputFp},
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
