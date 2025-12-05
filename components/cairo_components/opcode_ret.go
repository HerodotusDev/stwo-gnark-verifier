package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	RetOpcodeTraceColumns       = 12
	RetOpcodeInteractionColumns = 16
)

type RetOpcodeClaim struct {
	LogSize frontend.Variable
}

type RetOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type RetOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRetOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim RetOpcodeClaim,
	interactionClaim RetOpcodeInteractionClaim,
) RetOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return RetOpcodeComponent{
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

func (c RetOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(RetOpcodeTraceColumns, RetOpcodeInteractionColumns)

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
	nextPcID := traceSampledValues.Get(3)
	nextPcLimb0 := traceSampledValues.Get(4)
	nextPcLimb1 := traceSampledValues.Get(5)
	nextPcLimb2 := traceSampledValues.Get(6)
	nextFpID := traceSampledValues.Get(7)
	nextFpLimb0 := traceSampledValues.Get(8)
	nextFpLimb1 := traceSampledValues.Get(9)
	nextFpLimb2 := traceSampledValues.Get(10)
	enabler := traceSampledValues.Get(11)

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

	verifyInstructionSum := sub.DecodeInstruction15A61Evaluate(
		c.qm31,
		inputPc,
		c.verifyInstructionElements,
	)

	readNextPc := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Sub(inputFp, c.qm31.One()),
		nextPcID,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := readNextPc.AddressLookupSum
	memoryIdToBigSum2 := readNextPc.IdToBigLookupSum

	readNextFp := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Sub(inputFp, qm31Const(2)),
		nextFpID,
		nextFpLimb0,
		nextFpLimb1,
		nextFpLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum3 := readNextFp.AddressLookupSum
	memoryIdToBigSum4 := readNextFp.IdToBigLookupSum

	var err error
	opcodesSum5, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPcValue := c.qm31.Add(nextPcLimb0, c.qm31.Mul(nextPcLimb1, qm31Const(512)))
	nextPcValue = c.qm31.Add(nextPcValue, c.qm31.Mul(nextPcLimb2, qm31Const(262144)))

	nextFpValue := c.qm31.Add(nextFpLimb0, c.qm31.Mul(nextFpLimb1, qm31Const(512)))
	nextFpValue = c.qm31.Add(nextFpValue, c.qm31.Mul(nextFpLimb2, qm31Const(262144)))

	opcodesSum6, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{nextPcValue, inputAp, nextFpValue},
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
