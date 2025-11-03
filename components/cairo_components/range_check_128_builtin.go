package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type RangeCheck128BuiltinClaim struct {
	LogSize                uint32
	RangeCheckSegmentStart uint32
}

type RangeCheck128BuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck128BuiltinComponent struct {
	qm31 *m31.QM31Chip

	logSize uint8

	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheck128Builtin(
	qm31 *m31.QM31Chip,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	claim RangeCheck128BuiltinClaim,
	interactionClaim RangeCheck128BuiltinInteractionClaim,
) *RangeCheck128BuiltinComponent {
	if claim.LogSize > 255 {
		panic("range check 128 builtin log size must fit in uint8")
	}

	columnSize := uint64(1) << claim.LogSize
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(uint64(claim.RangeCheckSegmentStart)),
	)

	return &RangeCheck128BuiltinComponent{
		qm31:                      qm31,
		logSize:                   uint8(claim.LogSize),
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		segmentStart:              segmentStart,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(), // Assume vanishing polynomial evaluates to 1.
	}
}

func (c *RangeCheck128BuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(17, 4)

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
	limb11 := trace[12][0]
	limb12 := trace[13][0]
	limb13 := trace[14][0]
	limb14 := trace[15][0]
	msb := trace[16][0]

	eval := sub.ReadPositiveNumBits128Evaluate(
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
		limb11,
		limb12,
		limb13,
		limb14,
		msb,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = eval.Sum

	interaction := interactionSampledValues
	col0Prev := interaction[0][0]
	col0Curr := interaction[0][1]
	col1Prev := interaction[1][0]
	col1Curr := interaction[1][1]
	col2Prev := interaction[2][0]
	col2Curr := interaction[2][1]
	col3Prev := interaction[3][0]
	col3Curr := interaction[3][1]

	currBlock := c.qm31.FromPartialEvals(col0Curr, col1Curr, col2Curr, col3Curr)
	prevBlock := c.qm31.FromPartialEvals(col0Prev, col1Prev, col2Prev, col3Prev)

	term := c.qm31.Sub(currBlock, prevBlock)
	term = c.qm31.Add(term, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	product := c.qm31.Mul(term, c.qm31.Mul(eval.AddressLookupSum, eval.IdToBigLookupSum))
	constraint := c.qm31.Sub(product, c.qm31.Add(eval.AddressLookupSum, eval.IdToBigLookupSum))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
