package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheck18InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck18LogSize = 18

type RangeCheck18Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck18(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck18InteractionClaim,
) *RangeCheck18Component {
	return &RangeCheck18Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck18LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck18LogSize)},
		),
	}
}

func (c *RangeCheck18Component) Evaluate(
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
