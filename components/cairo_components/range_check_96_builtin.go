package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type RangeCheck96BuiltinClaim struct {
	LogSize                uint32
	RangeCheckSegmentStart uint32
}

type RangeCheck96BuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck96BuiltinComponent struct {
	qm31 *m31.QM31Chip

	logSize uint8

	memoryAddressToIdElements m31.InteractionElements
	rangeCheck6Elements       m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheck96Builtin(
	qm31 *m31.QM31Chip,
	memoryAddressToIdElements m31.InteractionElements,
	rangeCheck6Elements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	claim RangeCheck96BuiltinClaim,
	interactionClaim RangeCheck96BuiltinInteractionClaim,
) *RangeCheck96BuiltinComponent {
	if claim.LogSize > 255 {
		panic("range check 96 builtin log size must fit in uint8")
	}

	columnSize := uint64(1) << claim.LogSize
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(uint64(claim.RangeCheckSegmentStart)),
	)

	return &RangeCheck96BuiltinComponent{
		qm31:                      qm31,
		logSize:                   uint8(claim.LogSize),
		memoryAddressToIdElements: memoryAddressToIdElements,
		rangeCheck6Elements:       rangeCheck6Elements,
		memoryIdToBigElements:     memoryIdToBigElements,
		segmentStart:              segmentStart,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(), // Assume vanishing polynomial evaluates to 1.
	}
}

func (c *RangeCheck96BuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(12, 8)

	seqColumn := traces.Get(sequencePreprocessedColumn(c.logSize))
	input := c.qm31.Add(c.segmentStart, seqColumn)

	trace := traceSampledValues
	valueID := trace[0][0]
	limb0 := trace[1][0]
	limb1 := trace[2][0]
	limb2 := trace[3][0]
	limb3 := trace[4][0]
	limb4 := trace[5][0]
	limb5 := trace[6][0]
	limb6 := trace[7][0]
	limb7 := trace[8][0]
	limb8 := trace[9][0]
	limb9 := trace[10][0]
	limb10 := trace[11][0]

	eval := sub.ReadPositiveNumBits96Evaluate(
		c.qm31,
		input,
		valueID,
		limb0,
		limb1,
		limb2,
		limb3,
		limb4,
		limb5,
		limb6,
		limb7,
		limb8,
		limb9,
		limb10,
		c.memoryAddressToIdElements,
		c.rangeCheck6Elements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = eval.Sum

	interaction := interactionSampledValues
	tr0 := interaction[0][0]
	tr1 := interaction[1][0]
	tr2 := interaction[2][0]
	tr3 := interaction[3][0]

	tr4Prev := interaction[4][0]
	tr4Curr := interaction[4][1]
	tr5Prev := interaction[5][0]
	tr5Curr := interaction[5][1]
	tr6Prev := interaction[6][0]
	tr6Curr := interaction[6][1]
	tr7Prev := interaction[7][0]
	tr7Curr := interaction[7][1]

	firstBlock := c.qm31.FromPartialEvals(tr0, tr1, tr2, tr3)
	secondBlock := c.qm31.FromPartialEvals(tr4Curr, tr5Curr, tr6Curr, tr7Curr)
	prevSecondBlock := c.qm31.FromPartialEvals(tr4Prev, tr5Prev, tr6Prev, tr7Prev)

	// ((firstBlock * memAddrSum * rangeCheck6Sum) - memAddrSum - rangeCheck6Sum) == 0
	constraint := c.qm31.Mul(firstBlock, c.qm31.Mul(eval.AddressLookupSum, eval.RangeCheck6Sum))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(eval.AddressLookupSum, eval.RangeCheck6Sum))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// ((secondBlock - firstBlock - prevSecondBlock + claimedSum/columnSize) * memIdToBigSum - 1) == 0
	term := c.qm31.Sub(secondBlock, firstBlock)
	term = c.qm31.Sub(term, prevSecondBlock)
	term = c.qm31.Add(term, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint = c.qm31.Mul(term, eval.IdToBigLookupSum)
	constraint = c.qm31.Sub(constraint, c.qm31.One())
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
