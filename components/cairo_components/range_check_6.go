package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheck6InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck6LogSize = 6

type RangeCheck6Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck6(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck6InteractionClaim,
) *RangeCheck6Component {
	return &RangeCheck6Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck6LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck6LogSize)},
		),
	}
}

func (c *RangeCheck6Component) Evaluate(
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
