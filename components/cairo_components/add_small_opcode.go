package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type AddSmallOpcodeClaim struct {
	LogSize uint32
}

type AddSmallOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type AddSmallOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewAddSmallOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim AddSmallOpcodeClaim,
	interactionClaim AddSmallOpcodeInteractionClaim,
) *AddSmallOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &AddSmallOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(), // TODO: provide actual vanishing evaluation.
	}
}

func (c *AddSmallOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(33, 20)

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
	dstMSB := trace[15][0]
	dstMidSet := trace[16][0]
	dstLimb0 := trace[17][0]
	dstLimb1 := trace[18][0]
	dstLimb2 := trace[19][0]

	op0ID := trace[20][0]
	op0MSB := trace[21][0]
	op0MidSet := trace[22][0]
	op0Limb0 := trace[23][0]
	op0Limb1 := trace[24][0]
	op0Limb2 := trace[25][0]

	op1ID := trace[26][0]
	op1MSB := trace[27][0]
	op1MidSet := trace[28][0]
	op1Limb0 := trace[29][0]
	op1Limb1 := trace[30][0]
	op1Limb2 := trace[31][0]
	enabler := trace[32][0]

	// Enabler bit constraint.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

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

	// Constraint: if imm then offset2 is 1.
	constraint = c.qm31.Mul(
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

	dstRes := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(memDstBase, decoded.Offset0MinusBase),
		dstID,
		dstMSB,
		dstMidSet,
		dstLimb0,
		dstLimb1,
		dstLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum1 := dstRes.AddressLookupSum
	memIdBigSum2 := dstRes.IdToBigLookupSum
	sum = dstRes.Sum

	op0Res := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(mem0Base, decoded.Offset1MinusBase),
		op0ID,
		op0MSB,
		op0MidSet,
		op0Limb0,
		op0Limb1,
		op0Limb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum3 := op0Res.AddressLookupSum
	memIdBigSum4 := op0Res.IdToBigLookupSum
	sum = op0Res.Sum

	op1Res := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		op1ID,
		op1MSB,
		op1MidSet,
		op1Limb0,
		op1Limb1,
		op1Limb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum5 := op1Res.AddressLookupSum
	memIdBigSum6 := op1Res.IdToBigLookupSum
	sum = op1Res.Sum

	// dst limb equals sum.
	dstValue := dstRes.Value
	op0Value := op0Res.Value
	op1Value := op1Res.Value
	constraint = c.qm31.Sub(dstValue, c.qm31.Add(op0Value, op1Value))
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

	// Constraint group 0
	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifySum, memAddrSum1))
	constraint = c.qm31.Sub(constraint, verifySum)
	constraint = c.qm31.Sub(constraint, memAddrSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Group 1
	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memIdBigSum2, memAddrSum3))
	constraint = c.qm31.Sub(constraint, memIdBigSum2)
	constraint = c.qm31.Sub(constraint, memAddrSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Group 2
	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memIdBigSum4, memAddrSum5))
	constraint = c.qm31.Sub(constraint, memIdBigSum4)
	constraint = c.qm31.Sub(constraint, memAddrSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Group 3
	diff3 := c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff3, c.qm31.Mul(memIdBigSum6, opcodesSum0))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memIdBigSum6, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum0)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Group 4
	diff4 := c.qm31.Sub(part4, part3)
	diff4 = c.qm31.Sub(diff4, part4Prev)
	diff4 = c.qm31.Add(diff4, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff4, opcodesSum1), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
