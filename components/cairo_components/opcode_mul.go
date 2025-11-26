package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	mulOpcodeTraceColumns       = 130
	mulOpcodeInteractionColumns = 76
)

type MulOpcodeClaim struct {
	LogSize uints.U8
}

type MulOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type MulOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck19Elements      m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewMulOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim MulOpcodeClaim,
	interactionClaim MulOpcodeInteractionClaim,
) *MulOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &MulOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck19Elements:      rangeCheck19Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSize),
		vanishEvalInv:             qm31.One(),
	}
}

func (c *MulOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(mulOpcodeTraceColumns, mulOpcodeInteractionColumns)

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
	dstLimbs := traceSampledValues.Slice(15, 28)
	op0ID := traceSampledValues.Get(43)
	op0Limbs := traceSampledValues.Slice(44, 28)
	op1ID := traceSampledValues.Get(72)
	op1Limbs := traceSampledValues.Slice(73, 28)
	k := traceSampledValues.Get(101)
	carries := traceSampledValues.Slice(102, 27)
	enabler := traceSampledValues.Get(129)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 19)
	for i := 0; i < 18; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, 4*i, 0)
	}
	prevRowPartial := interactionSampledValues.Partial(c.qm31, 72, 0)
	partials[18] = interactionSampledValues.Partial(c.qm31, 72, 1)

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

	dstRes := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		dstAddr,
		dstID,
		dstLimbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum1 := dstRes.AddressLookupSum
	memIdBigSum2 := dstRes.IdToBigLookupSum

	op0Res := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		op0Addr,
		op0ID,
		op0Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum3 := op0Res.AddressLookupSum
	memIdBigSum4 := op0Res.IdToBigLookupSum

	op1Res := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		op1Addr,
		op1ID,
		op1Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memAddrSum5 := op1Res.AddressLookupSum
	memIdBigSum6 := op1Res.IdToBigLookupSum

	verifyRes := sub.VerifyMul252Evaluate(
		c.qm31,
		op0Limbs,
		op1Limbs,
		dstLimbs,
		k,
		carries,
		c.rangeCheck19Elements,
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

	constraint = c.qm31.Mul(partials[0], c.qm31.Mul(verifySum, memAddrSum1))
	constraint = c.qm31.Sub(constraint, verifySum)
	constraint = c.qm31.Sub(constraint, memAddrSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff := c.qm31.Sub(partials[1], partials[0])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum2, memAddrSum3))
	constraint = c.qm31.Sub(constraint, memIdBigSum2)
	constraint = c.qm31.Sub(constraint, memAddrSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[2], partials[1])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum4, memAddrSum5))
	constraint = c.qm31.Sub(constraint, memIdBigSum4)
	constraint = c.qm31.Sub(constraint, memAddrSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[3], partials[2])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memIdBigSum6, rangeCheckSums[0]))
	constraint = c.qm31.Sub(constraint, memIdBigSum6)
	constraint = c.qm31.Sub(constraint, rangeCheckSums[0])
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	rcIndex := 1
	for i := 4; i <= 16; i++ {
		diff = c.qm31.Sub(partials[i], partials[i-1])
		left := rangeCheckSums[rcIndex]
		right := rangeCheckSums[rcIndex+1]
		constraint = c.qm31.Mul(diff, c.qm31.Mul(left, right))
		constraint = c.qm31.Sub(constraint, left)
		constraint = c.qm31.Sub(constraint, right)
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
		rcIndex += 2
	}

	diff = c.qm31.Sub(partials[17], partials[16])
	rcFinal := rangeCheckSums[rcIndex]
	constraint = c.qm31.Mul(diff, c.qm31.Mul(rcFinal, opcodesSum0))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(rcFinal, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum0)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[18], partials[17])
	diff = c.qm31.Sub(diff, prevRowPartial)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff, opcodesSum1), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
