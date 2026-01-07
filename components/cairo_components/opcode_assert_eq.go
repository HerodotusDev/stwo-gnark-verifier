package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	AssertEqOpcodeTraceColumns       = 12
	AssertEqOpcodeInteractionColumns = 12
)

type AssertEqOpcodeClaim struct {
	LogSize frontend.Variable
}

type AssertEqOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type AssertEqOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIDElements m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewAssertEqOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIDElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim AssertEqOpcodeClaim,
	interactionClaim AssertEqOpcodeInteractionClaim,
) AssertEqOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return AssertEqOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIDElements: memoryAddressToIDElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c AssertEqOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(AssertEqOpcodeTraceColumns, AssertEqOpcodeInteractionColumns)

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
	offset2 := traceSampledValues.Get(4)
	dstBaseFP := traceSampledValues.Get(5)
	op1BaseFP := traceSampledValues.Get(6)
	apUpdateAdd1 := traceSampledValues.Get(7)
	memDstBase := traceSampledValues.Get(8)
	mem1Base := traceSampledValues.Get(9)
	dstID := traceSampledValues.Get(10)
	enabler := traceSampledValues.Get(11)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 1)
	part2Prev := interactionSampledValues.Partial(c.qm31, 8, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstructionFE864Evaluate(
		c.qm31,
		inputPc,
		offset0,
		offset2,
		dstBaseFP,
		op1BaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	// mem_dst_base relation.
	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(c.qm31.One(), dstBaseFP), inputAp),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// mem1_base relation.
	mem1Expected := c.qm31.Add(
		c.qm31.Mul(op1BaseFP, inputFp),
		c.qm31.Mul(decoded.Op1BaseAP, inputAp),
	)
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	memVerify := sub.MemVerifyEqualEvaluate(
		c.qm31,
		c.qm31.Add(memDstBase, decoded.Offset0MinusBase),
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		dstID,
		c.memoryAddressToIDElements,
		sum,
	)
	memoryAddressSum1 := memVerify.AddressLookupSum1
	memoryAddressSum2 := memVerify.AddressLookupSum2
	sum = memVerify.Sum

	var err error
	opcodesSum3, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	opcodesSum4, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			c.qm31.Add(inputPc, c.qm31.One()),
			c.qm31.Add(inputAp, apUpdateAdd1),
			inputFp,
		},
	)
	if err != nil {
		panic(err)
	}

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifyInstructionSum, memoryAddressSum1))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryAddressSum2, opcodesSum3))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryAddressSum2, enabler))
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
