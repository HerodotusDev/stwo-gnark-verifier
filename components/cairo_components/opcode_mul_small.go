package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	MulSmallOpcodeTraceColumns       = 37
	MulSmallOpcodeInteractionColumns = 24
)

type MulSmallOpcodeClaim struct {
	LogSize frontend.Variable
}

type MulSmallOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type MulSmallOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck11Elements      m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewMulSmallOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck11Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim MulSmallOpcodeClaim,
	interactionClaim MulSmallOpcodeInteractionClaim,
) MulSmallOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInvQM := qm31.Inverse(columnSize)

	return MulSmallOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck11Elements:      rangeCheck11Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInvQM,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c MulSmallOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(MulSmallOpcodeTraceColumns, MulSmallOpcodeInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	one := c.qm31.One()

	inputPC := traceSampledValues.Get(0)
	inputAP := traceSampledValues.Get(1)
	inputFP := traceSampledValues.Get(2)
	offset0 := traceSampledValues.Get(3)
	offset1 := traceSampledValues.Get(4)
	offset2 := traceSampledValues.Get(5)
	dstBaseFP := traceSampledValues.Get(6)
	op0BaseFP := traceSampledValues.Get(7)
	op1Imm := traceSampledValues.Get(8)
	op1BaseFP := traceSampledValues.Get(9)
	apUpdateAdd1 := traceSampledValues.Get(10)
	memDstBase := traceSampledValues.Get(11)
	mem0Base := traceSampledValues.Get(12)
	mem1Base := traceSampledValues.Get(13)
	dstID := traceSampledValues.Get(14)
	dstLimbs := traceSampledValues.Slice(15, 8)
	op0ID := traceSampledValues.Get(23)
	op0Limbs := traceSampledValues.Slice(24, 4)
	op1ID := traceSampledValues.Get(28)
	op1Limbs := traceSampledValues.Slice(29, 4)
	carry1 := traceSampledValues.Get(33)
	carry3 := traceSampledValues.Get(34)
	carry5 := traceSampledValues.Get(35)
	enabler := traceSampledValues.Get(36)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 0)
	part4 := interactionSampledValues.Partial(c.qm31, 16, 0)
	part5Prev := interactionSampledValues.Partial(c.qm31, 20, 0)
	part5 := interactionSampledValues.Partial(c.qm31, 20, 1)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstruction4B8CFEvaluate(
		c.qm31,
		inputPC,
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
	op1BaseAP := decoded.Op1BaseAP
	sum = decoded.Sum

	constraint = c.qm31.Mul(op1Imm, c.qm31.Sub(one, decoded.Offset2MinusBase))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFP),
		c.qm31.Mul(c.qm31.Sub(one, dstBaseFP), inputAP),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	mem0Expected := c.qm31.Add(
		c.qm31.Mul(op0BaseFP, inputFP),
		c.qm31.Mul(c.qm31.Sub(one, op0BaseFP), inputAP),
	)
	constraint = c.qm31.Sub(mem0Base, mem0Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	mem1Expected := c.qm31.Add(
		c.qm31.Mul(op1Imm, inputPC),
		c.qm31.Mul(op1BaseFP, inputFP),
	)
	mem1Expected = c.qm31.Add(mem1Expected, c.qm31.Mul(op1BaseAP, inputAP))
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	dstAddr := c.qm31.Add(memDstBase, decoded.Offset0MinusBase)
	op0Addr := c.qm31.Add(mem0Base, decoded.Offset1MinusBase)
	op1Addr := c.qm31.Add(mem1Base, decoded.Offset2MinusBase)

	dstRes := sub.ReadPositiveNumBits72Evaluate(
		c.qm31,
		dstAddr,
		dstID,
		dstLimbs[0], dstLimbs[1], dstLimbs[2], dstLimbs[3],
		dstLimbs[4], dstLimbs[5], dstLimbs[6], dstLimbs[7],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum1 := dstRes.AddressLookupSum
	memIdBigSum2 := dstRes.IdToBigLookupSum
	sum = dstRes.Sum

	op0Res := sub.ReadPositiveNumBits36Evaluate(
		c.qm31,
		op0Addr,
		op0ID,
		op0Limbs[0], op0Limbs[1], op0Limbs[2], op0Limbs[3],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum3 := op0Res.AddressLookupSum
	memIdBigSum4 := op0Res.IdToBigLookupSum
	sum = op0Res.Sum

	op1Res := sub.ReadPositiveNumBits36Evaluate(
		c.qm31,
		op1Addr,
		op1ID,
		op1Limbs[0], op1Limbs[1], op1Limbs[2], op1Limbs[3],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memAddrSum5 := op1Res.AddressLookupSum
	memIdBigSum6 := op1Res.IdToBigLookupSum
	sum = op1Res.Sum

	verifyRes := sub.VerifyMulSmallEvaluate(
		c.qm31,
		op0Limbs,
		op1Limbs,
		dstLimbs,
		carry1,
		carry3,
		carry5,
		c.rangeCheck11Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = verifyRes.Sum
	rangeCheckSums := verifyRes.RangeCheckSums

	opcodesSum0, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPC, inputAP, inputFP},
	)
	if err != nil {
		panic(err)
	}

	opcodesSum1, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			c.qm31.Add(c.qm31.Add(inputPC, one), op1Imm),
			c.qm31.Add(inputAP, apUpdateAdd1),
			inputFP,
		},
	)
	if err != nil {
		panic(err)
	}

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifySum, memAddrSum1))
	constraint = c.qm31.Sub(constraint, verifySum)
	constraint = c.qm31.Sub(constraint, memAddrSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum2, memAddrSum3))
	constraint = c.qm31.Sub(constraint, memIdBigSum2)
	constraint = c.qm31.Sub(constraint, memAddrSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum4, memAddrSum5))
	constraint = c.qm31.Sub(constraint, memIdBigSum4)
	constraint = c.qm31.Sub(constraint, memAddrSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum6, rangeCheckSums[0]))
	constraint = c.qm31.Sub(constraint, memIdBigSum6)
	constraint = c.qm31.Sub(constraint, rangeCheckSums[0])
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(part4, part3)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(rangeCheckSums[1], rangeCheckSums[2]))
	constraint = c.qm31.Sub(constraint, rangeCheckSums[1])
	constraint = c.qm31.Sub(constraint, rangeCheckSums[2])
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(part5, part4)
	diff = c.qm31.Sub(diff, part5Prev)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Mul(diff, c.qm31.Mul(opcodesSum0, opcodesSum1))
	constraint = c.qm31.Add(constraint, c.qm31.Mul(opcodesSum0, enabler))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(opcodesSum1, enabler))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
