package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type AddOpcodeClaim struct {
	LogSize uint32
}

type AddOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type AddOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewAddOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim AddOpcodeClaim,
	interactionClaim AddOpcodeInteractionClaim,
) *AddOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &AddOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(), // TODO: actual vanishing evaluation.
	}
}

func (c *AddOpcodeComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	trace := traceSampledValues

	inputPc := trace[0][0]
	inputAp := trace[1][0]
	inputFp := trace[2][0]
	offset0 := trace[3][0]
	offset1 := trace[4][0]
	offset2 := trace[5][0]
	dstBaseFP := trace[6][0]
	op0BaseFP := trace[7][0]
	op1Imm := trace[8][0]
	op1BaseFP := trace[9][0]
	apUpdateAdd1 := trace[10][0]
	memDstBase := trace[11][0]
	mem0Base := trace[12][0]
	mem1Base := trace[13][0]
	dstID := trace[14][0]

	dstLimbs := gatherLimbs(trace, 15, 28)
	op0ID := trace[43][0]
	op0Limbs := gatherLimbs(trace, 44, 28)
	op1ID := trace[72][0]
	op1Limbs := gatherLimbs(trace, 73, 28)
	subPBit := trace[101][0]
	enabler := trace[102][0]

	decoded := sub.DecodeInstructionBC3CDEvaluate(
		c.qm31,
		inputPc,
		offset0,
		offset1,
		offset2,
		dstBaseFP,
		op0BaseFP,
		op1Imm,
		op1BaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifySum := decoded.VerifySum
	sum = decoded.Sum

	// Constraint - if imm then offset2 is 1.
	constraint := c.qm31.Mul(
		op1Imm,
		c.qm31.Sub(c.qm31.One(), decoded.Offset2MinusBase),
	)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem_dst_base relation.
	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(c.qm31.One(), dstBaseFP), inputAp),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem0_base relation.
	mem0Expected := c.qm31.Add(
		c.qm31.Mul(op0BaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(c.qm31.One(), op0BaseFP), inputAp),
	)
	constraint = c.qm31.Sub(mem0Base, mem0Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem1_base relation.
	mem1Expected := c.qm31.Add(
		c.qm31.Add(
			c.qm31.Mul(op1Imm, inputPc),
			c.qm31.Mul(op1BaseFP, inputFp),
		),
		c.qm31.Mul(decoded.Op1BaseAP, inputAp),
	)
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	dstResult := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(memDstBase, decoded.Offset0MinusBase),
		dstID,
		dstLimbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum1 := dstResult.AddressLookupSum
	memIdBigSum2 := dstResult.IdToBigLookupSum

	op0Result := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(mem0Base, decoded.Offset1MinusBase),
		op0ID,
		op0Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum3 := op0Result.AddressLookupSum
	memIdBigSum4 := op0Result.IdToBigLookupSum

	op1Result := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		op1ID,
		op1Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum5 := op1Result.AddressLookupSum
	memIdBigSum6 := op1Result.IdToBigLookupSum

	sum = sub.VerifyAdd252Evaluate(
		c.qm31,
		op0Limbs,
		op1Limbs,
		dstLimbs,
		subPBit,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

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
			c.qm31.Add(c.qm31.Add(inputPc, c.qm31.One()), op1Imm),
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
		interactionSampledValues[12][0],
		interactionSampledValues[13][0],
		interactionSampledValues[14][0],
		interactionSampledValues[15][0],
	)
	part4Prev := c.qm31.FromPartialEvals(
		interactionSampledValues[16][0],
		interactionSampledValues[17][0],
		interactionSampledValues[18][0],
		interactionSampledValues[19][0],
	)
	part4 := c.qm31.FromPartialEvals(
		interactionSampledValues[16][1],
		interactionSampledValues[17][1],
		interactionSampledValues[18][1],
		interactionSampledValues[19][1],
	)

	// Constraint 0
	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifySum, memAddrSum1))
	constraint = c.qm31.Sub(constraint, verifySum)
	constraint = c.qm31.Sub(constraint, memAddrSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 1
	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memIdBigSum2, memAddrSum3))
	constraint = c.qm31.Sub(constraint, memIdBigSum2)
	constraint = c.qm31.Sub(constraint, memAddrSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 2
	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memIdBigSum4, memAddrSum5))
	constraint = c.qm31.Sub(constraint, memIdBigSum4)
	constraint = c.qm31.Sub(constraint, memAddrSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 3
	diff3 := c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff3, c.qm31.Mul(memIdBigSum6, opcodesSum0))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memIdBigSum6, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum0)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff4 := c.qm31.Sub(part4, part3)
	diff4 = c.qm31.Sub(diff4, part4Prev)
	diff4 = c.qm31.Add(diff4, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff4, opcodesSum1), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}

func gatherLimbs(trace [][]m31.QM31, start int, count int) []m31.QM31 {
	limbs := make([]m31.QM31, count)
	for i := 0; i < count; i++ {
		limbs[i] = trace[start+i][0]
	}
	return limbs
}
