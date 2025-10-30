package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type JnzOpcodeClaim struct {
	LogSize uint32
}

type JnzOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JnzOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJnzOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JnzOpcodeClaim,
	interactionClaim JnzOpcodeInteractionClaim,
) *JnzOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &JnzOpcodeComponent{
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

func (c *JnzOpcodeComponent) Evaluate(
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
	enabler := trace[36][0]

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
	memoryAddressSum := dstLookup.AddressLookupSum
	memoryIdToBigSum := dstLookup.IdToBigLookupSum

	// dst equals zero.
	total := dstLimbs[0]
	for i := 1; i < len(dstLimbs); i++ {
		total = c.qm31.Add(total, dstLimbs[i])
	}
	constraint = c.qm31.Mul(total, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	opcodesSum3, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, qm31Const(2))
	nextAp := c.qm31.Add(inputAp, apUpdateAdd1)

	opcodesSum4, err := c.qm31.Combine(
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

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifyInstructionSum, memoryAddressSum))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum, opcodesSum3))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum, enabler))
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
