package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	addOpcodeTraceColumns       = 103
	addOpcodeInteractionColumns = 20
)

type AddOpcodeClaim struct {
	LogSize uints.U8
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
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim AddOpcodeClaim,
	interactionClaim AddOpcodeInteractionClaim,
) *AddOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return &AddOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c *AddOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(addOpcodeTraceColumns, addOpcodeInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputPc := traceSampledValues.Get(0)
	inputAp := traceSampledValues.Get(1)
	inputFp := traceSampledValues.Get(2)
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
	dstLimbs := traceSampledValues.Slice(15, 28)
	op0ID := traceSampledValues.Get(43)
	op0Limbs := traceSampledValues.Slice(44, 28)
	op1ID := traceSampledValues.Get(72)
	op1Limbs := traceSampledValues.Slice(73, 28)
	subPBit := traceSampledValues.Get(101)
	enabler := traceSampledValues.Get(102)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 0)
	part4Prev := interactionSampledValues.Partial(c.qm31, 16, 0)
	part4 := interactionSampledValues.Partial(c.qm31, 16, 1)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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

	// Constraint - if imm then offset2 is 1.
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
