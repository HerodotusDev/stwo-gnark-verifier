package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	AddSmallOpcodeTraceColumns       = 33
	AddSmallOpcodeInteractionColumns = 20
)

type AddSmallOpcodeClaim struct {
	LogSize frontend.Variable
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
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim AddSmallOpcodeClaim,
	interactionClaim AddSmallOpcodeInteractionClaim,
) AddSmallOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return AddSmallOpcodeComponent{
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

func (c AddSmallOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(AddSmallOpcodeTraceColumns, AddSmallOpcodeInteractionColumns)

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
	dstMSB := traceSampledValues.Get(15)
	dstMidSet := traceSampledValues.Get(16)
	dstLimb0 := traceSampledValues.Get(17)
	dstLimb1 := traceSampledValues.Get(18)
	dstLimb2 := traceSampledValues.Get(19)
	op0ID := traceSampledValues.Get(20)
	op0MSB := traceSampledValues.Get(21)
	op0MidSet := traceSampledValues.Get(22)
	op0Limb0 := traceSampledValues.Get(23)
	op0Limb1 := traceSampledValues.Get(24)
	op0Limb2 := traceSampledValues.Get(25)
	op1ID := traceSampledValues.Get(26)
	op1MSB := traceSampledValues.Get(27)
	op1MidSet := traceSampledValues.Get(28)
	op1Limb0 := traceSampledValues.Get(29)
	op1Limb1 := traceSampledValues.Get(30)
	op1Limb2 := traceSampledValues.Get(31)
	enabler := traceSampledValues.Get(32)

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
