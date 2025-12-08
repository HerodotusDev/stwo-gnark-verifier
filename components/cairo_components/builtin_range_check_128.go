package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	RangeCheck128BuiltinTraceColumns       = 17
	RangeCheck128BuiltinInteractionColumns = 4
)

type RangeCheck128BuiltinClaim struct {
	LogSize                frontend.Variable
	RangeCheckSegmentStart frontend.Variable
}

type RangeCheck128BuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck128BuiltinComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	logSize frontend.Variable

	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheck128Builtin(
	api frontend.API,
	qm31 *m31.QM31Chip,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim RangeCheck128BuiltinClaim,
	interactionClaim RangeCheck128BuiltinInteractionClaim,
) RangeCheck128BuiltinComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(claim.RangeCheckSegmentStart),
	)

	return RangeCheck128BuiltinComponent{
		api:                       api,
		qm31:                      qm31,
		logSize:                   claim.LogSize,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		segmentStart:              segmentStart,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c RangeCheck128BuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(RangeCheck128BuiltinTraceColumns, RangeCheck128BuiltinInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seqColumn := traces.Get(NewPreprocessedColumnSeq(c.api, c.logSize))
	input := c.qm31.Add(c.segmentStart, seqColumn)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	valueID := traceSampledValues.Get(0)
	limb0 := traceSampledValues.Get(1)
	limb1 := traceSampledValues.Get(2)
	limb2 := traceSampledValues.Get(3)
	limb3 := traceSampledValues.Get(4)
	limb4 := traceSampledValues.Get(5)
	limb5 := traceSampledValues.Get(6)
	limb6 := traceSampledValues.Get(7)
	limb7 := traceSampledValues.Get(8)
	limb8 := traceSampledValues.Get(9)
	limb9 := traceSampledValues.Get(10)
	limb10 := traceSampledValues.Get(11)
	limb11 := traceSampledValues.Get(12)
	limb12 := traceSampledValues.Get(13)
	limb13 := traceSampledValues.Get(14)
	limb14 := traceSampledValues.Get(15)
	msb := traceSampledValues.Get(16)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	currBlock := interactionSampledValues.Partial(c.qm31, 0, 1)
	prevBlock := interactionSampledValues.Partial(c.qm31, 0, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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

	term := c.qm31.Sub(currBlock, prevBlock)
	term = c.qm31.Add(term, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	product := c.qm31.Mul(term, c.qm31.Mul(eval.AddressLookupSum, eval.IdToBigLookupSum))
	constraint := c.qm31.Sub(product, c.qm31.Add(eval.AddressLookupSum, eval.IdToBigLookupSum))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
