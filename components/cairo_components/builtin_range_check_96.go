package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	RangeCheck96BuiltinTraceColumns       = 12
	RangeCheck96BuiltinInteractionColumns = 8
)

type RangeCheck96BuiltinClaim struct {
	LogSize                frontend.Variable
	RangeCheckSegmentStart frontend.Variable
}

type RangeCheck96BuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck96BuiltinComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	logSize frontend.Variable

	memoryAddressToIdElements m31.InteractionElements
	rangeCheck6Elements       m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheck96Builtin(
	api frontend.API,
	qm31 *m31.QM31Chip,
	memoryAddressToIdElements m31.InteractionElements,
	rangeCheck6Elements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim RangeCheck96BuiltinClaim,
	interactionClaim RangeCheck96BuiltinInteractionClaim,
) RangeCheck96BuiltinComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(claim.RangeCheckSegmentStart),
	)

	return RangeCheck96BuiltinComponent{
		api:                       api,
		qm31:                      qm31,
		logSize:                   claim.LogSize,
		memoryAddressToIdElements: memoryAddressToIdElements,
		rangeCheck6Elements:       rangeCheck6Elements,
		memoryIdToBigElements:     memoryIdToBigElements,
		segmentStart:              segmentStart,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c RangeCheck96BuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(RangeCheck96BuiltinTraceColumns, RangeCheck96BuiltinInteractionColumns)

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

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	firstBlock := interactionSampledValues.Partial(c.qm31, 0, 0)
	secondBlock := interactionSampledValues.Partial(c.qm31, 4, 1)
	prevSecondBlock := interactionSampledValues.Partial(c.qm31, 4, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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
