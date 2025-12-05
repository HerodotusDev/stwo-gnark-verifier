package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	JumpRelImmOpcodeTraceColumns       = 11
	JumpRelImmOpcodeInteractionColumns = 12
)

type JumpRelImmOpcodeClaim struct {
	LogSize frontend.Variable
}

type JumpRelImmOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JumpRelImmOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJumpRelImmOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim JumpRelImmOpcodeClaim,
	interactionClaim JumpRelImmOpcodeInteractionClaim,
) JumpRelImmOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return JumpRelImmOpcodeComponent{
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

func (c JumpRelImmOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(JumpRelImmOpcodeTraceColumns, JumpRelImmOpcodeInteractionColumns)

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
	apUpdateAdd1 := traceSampledValues.Get(3)
	nextPcID := traceSampledValues.Get(4)
	msb := traceSampledValues.Get(5)
	midLimbsSet := traceSampledValues.Get(6)
	nextPcLimb0 := traceSampledValues.Get(7)
	nextPcLimb1 := traceSampledValues.Get(8)
	nextPcLimb2 := traceSampledValues.Get(9)
	enabler := traceSampledValues.Get(10)

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

	verifyInstructionSum, sum := sub.DecodeInstruction7EBC4Evaluate(
		c.qm31,
		inputPc,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	readNextPc := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(inputPc, c.qm31.One()),
		nextPcID,
		msb,
		midLimbsSet,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressSum1 := readNextPc.AddressLookupSum
	memoryIdToBigSum2 := readNextPc.IdToBigLookupSum
	sum = readNextPc.Sum

	var err error
	opcodesSum3, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, readNextPc.Value)

	opcodesSum4, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			nextPc,
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
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum2, opcodesSum3))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum2, enabler))
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
