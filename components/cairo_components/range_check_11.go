package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const rangeCheck11LogSize = 11

// +---------------------------------------+
// | Range Check 11 Interaction Claim Data |
// +---------------------------------------+
type RangeCheck11InteractionClaim struct {
	ClaimedSum m31.QM31
}

// +-----------------------------------------+
// | Range Check 11 Component Implementation |
// +-----------------------------------------+
type RangeCheck11Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck11(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck11InteractionClaim,
) *RangeCheck11Component {
	return &RangeCheck11Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck11LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck11LogSize)},
		),
	}
}

func (c *RangeCheck11Component) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	return c.inner.Evaluate(
		sum,
		preprocessedSampledValues,
		traceSampledValues,
		interactionSampledValues,
		randomCoeff,
	)
}
