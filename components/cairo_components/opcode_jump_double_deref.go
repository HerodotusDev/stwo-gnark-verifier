package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	jumpDoubleDerefOpcodeTraceColumns       = 17
	jumpDoubleDerefOpcodeInteractionColumns = 16
)

type JumpDoubleDerefOpcodeClaim struct {
	LogSize uints.U8
}

type JumpDoubleDerefOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JumpDoubleDerefOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJumpDoubleDerefOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JumpDoubleDerefOpcodeClaim,
	interactionClaim JumpDoubleDerefOpcodeInteractionClaim,
) *JumpDoubleDerefOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return &JumpDoubleDerefOpcodeComponent{
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

func (c *JumpDoubleDerefOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(jumpDoubleDerefOpcodeTraceColumns, jumpDoubleDerefOpcodeInteractionColumns)

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
	offset1 := traceSampledValues.Get(3)
	offset2 := traceSampledValues.Get(4)
	op0BaseFP := traceSampledValues.Get(5)
	apUpdateAdd1 := traceSampledValues.Get(6)
	mem0Base := traceSampledValues.Get(7)
	mem1BaseID := traceSampledValues.Get(8)
	mem1Limb0 := traceSampledValues.Get(9)
	mem1Limb1 := traceSampledValues.Get(10)
	mem1Limb2 := traceSampledValues.Get(11)
	nextPcID := traceSampledValues.Get(12)
	nextPcLimb0 := traceSampledValues.Get(13)
	nextPcLimb1 := traceSampledValues.Get(14)
	nextPcLimb2 := traceSampledValues.Get(15)
	enabler := traceSampledValues.Get(16)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 1)
	part3Prev := interactionSampledValues.Partial(c.qm31, 12, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstruction9BD86Evaluate(
		c.qm31,
		inputPc,
		offset1,
		offset2,
		op0BaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	// mem0_base relation.
	mem0Expected := c.qm31.Add(
		c.qm31.Mul(op0BaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(c.qm31.One(), op0BaseFP), inputAp),
	)
	constraint = c.qm31.Sub(mem0Base, mem0Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readMem1Base := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem0Base, decoded.Offset1MinusBase),
		mem1BaseID,
		mem1Limb0,
		mem1Limb1,
		mem1Limb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := readMem1Base.AddressLookupSum
	memoryIdToBigSum2 := readMem1Base.IdToBigLookupSum

	mem1Value := c.qm31.Add(
		c.qm31.Add(mem1Limb0, c.qm31.Mul(mem1Limb1, qm31Const(512))),
		c.qm31.Mul(mem1Limb2, qm31Const(262144)),
	)

	readNextPc := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem1Value, decoded.Offset2MinusBase),
		nextPcID,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum3 := readNextPc.AddressLookupSum
	memoryIdToBigSum4 := readNextPc.IdToBigLookupSum

	var err error
	opcodesSum5, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPcValue := c.qm31.Add(
		c.qm31.Add(nextPcLimb0, c.qm31.Mul(nextPcLimb1, qm31Const(512))),
		c.qm31.Mul(nextPcLimb2, qm31Const(262144)),
	)

	opcodesSum6, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			nextPcValue,
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
