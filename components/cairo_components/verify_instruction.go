package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type VerifyInstructionClaim struct {
	LogSize uint32
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
	qm31 *m31.QM31Chip,
	rangeCheck7_2_5Elements m31.InteractionElements,
	rangeCheck4_3Elements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	verifyInstructionElements m31.InteractionElements,
	claim VerifyInstructionClaim,
	interactionClaim VerifyInstructionInteractionClaim,
) *VerifyInstructionComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &VerifyInstructionComponent{
		qm31:                      qm31,
		rangeCheck7_2_5Elements:   rangeCheck7_2_5Elements,
		rangeCheck4_3Elements:     rangeCheck4_3Elements,
		memoryAddressElements:     memoryAddressElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		verifyInstructionElements: verifyInstructionElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSizeQM),
		vanishEvalInv:             qm31.One(),
	}
}

func (c *VerifyInstructionComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	trace := traceSampledValues

	inputPC := trace[0][0]
	offset0 := trace[1][0]
	offset1 := trace[2][0]
	offset2 := trace[3][0]
	instFelt5High := trace[4][0]
	instFelt6 := trace[5][0]
	opcodeExtension := trace[6][0]
	offset0Low := trace[7][0]
	offset0Mid := trace[8][0]
	offset1Low := trace[9][0]
	offset1Mid := trace[10][0]
	offset1High := trace[11][0]
	offset2Low := trace[12][0]
	offset2Mid := trace[13][0]
	offset2High := trace[14][0]
	instructionID := trace[15][0]
	enabler := trace[16][0]

	// No boolean constraint on enabler in Cairo (vanishing enforced via eqs only).

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

	part := func(start int, offset int) m31.QM31 {
		return c.qm31.FromPartialEvals(
			interactionSampledValues[start][offset],
			interactionSampledValues[start+1][offset],
			interactionSampledValues[start+2][offset],
			interactionSampledValues[start+3][offset],
		)
	}

	part0 := part(0, 0)
	part1 := part(4, 0)
	part2 := part(8, 1)
	part2Prev := part(8, 0)

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
