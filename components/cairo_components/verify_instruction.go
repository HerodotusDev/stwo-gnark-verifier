package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	verifyInstructionTraceColumns       = 17
	verifyInstructionInteractionColumns = 12
)

type VerifyInstructionClaim struct {
	LogSize uints.U8
}

type VerifyInstructionInteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyInstructionComponent struct {
	qm31 *m31.QM31Chip

	rangeCheck7_2_5Elements   m31.InteractionElements
	rangeCheck4_3Elements     m31.InteractionElements
	memoryAddressElements     m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	verifyInstructionElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewVerifyInstruction(
	api frontend.API,
	qm31 *m31.QM31Chip,
	rangeCheck7_2_5Elements m31.InteractionElements,
	rangeCheck4_3Elements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	verifyInstructionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim VerifyInstructionClaim,
	interactionClaim VerifyInstructionInteractionClaim,
) *VerifyInstructionComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &VerifyInstructionComponent{
		qm31:                      qm31,
		rangeCheck7_2_5Elements:   rangeCheck7_2_5Elements,
		rangeCheck4_3Elements:     rangeCheck4_3Elements,
		memoryAddressElements:     memoryAddressElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		verifyInstructionElements: verifyInstructionElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSize),
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c *VerifyInstructionComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(verifyInstructionTraceColumns, verifyInstructionInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputPC := traceSampledValues.Get(0)
	offset0 := traceSampledValues.Get(1)
	offset1 := traceSampledValues.Get(2)
	offset2 := traceSampledValues.Get(3)
	instFelt5High := traceSampledValues.Get(4)
	instFelt6 := traceSampledValues.Get(5)
	opcodeExtension := traceSampledValues.Get(6)
	offset0Low := traceSampledValues.Get(7)
	offset0Mid := traceSampledValues.Get(8)
	offset1Low := traceSampledValues.Get(9)
	offset1Mid := traceSampledValues.Get(10)
	offset1High := traceSampledValues.Get(11)
	offset2Low := traceSampledValues.Get(12)
	offset2Mid := traceSampledValues.Get(13)
	offset2High := traceSampledValues.Get(14)
	instructionID := traceSampledValues.Get(15)
	enabler := traceSampledValues.Get(16)

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

	offsets := sub.EncodeOffsetsEvaluate(
		c.qm31,
		offset0,
		offset1,
		offset2,
		offset0Low,
		offset0Mid,
		offset1Low,
		offset1Mid,
		offset1High,
		offset2Low,
		offset2Mid,
		offset2High,
		c.rangeCheck7_2_5Elements,
		c.rangeCheck4_3Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	valueLimbs := []m31.QM31{
		offset0Low,
		offsets.Offset1Combined,
		offset1Mid,
		offsets.Offset2Combined,
		offset2Mid,
		c.qm31.Add(offset2High, instFelt5High),
		instFelt6,
		opcodeExtension,
	}

	zero := qm31Const(0)
	for len(valueLimbs) < 28 {
		valueLimbs = append(valueLimbs, zero)
	}

	mem := sub.MemVerifyEvaluate(
		c.qm31,
		inputPC,
		valueLimbs,
		instructionID,
		c.memoryAddressElements,
		c.memoryIdToBigElements,
		offsets.Sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = mem.Sum

	verifySum, err := c.qm31.Combine(
		c.verifyInstructionElements,
		[]m31.QM31{
			inputPC,
			offset0,
			offset1,
			offset2,
			instFelt5High,
			instFelt6,
			opcodeExtension,
		},
	)
	if err != nil {
		panic(err)
	}

	constraint := c.qm31.Mul(part0, c.qm31.Mul(offsets.Range7_2_5Sum, offsets.Range4_3Sum))
	constraint = c.qm31.Sub(constraint, offsets.Range7_2_5Sum)
	constraint = c.qm31.Sub(constraint, offsets.Range4_3Sum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(mem.AddressLookupSum, mem.IdToBigLookupSum))
	constraint = c.qm31.Sub(constraint, mem.AddressLookupSum)
	constraint = c.qm31.Sub(constraint, mem.IdToBigLookupSum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(part2, part1)
	diff = c.qm31.Sub(diff, part2Prev)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint = c.qm31.Mul(diff, verifySum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
