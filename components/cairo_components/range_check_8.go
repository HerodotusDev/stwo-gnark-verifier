package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheck8InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck8LogSize = 8

type RangeCheck8Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck8(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck8InteractionClaim,
) *RangeCheck8Component {
	return &RangeCheck8Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck8LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck8LogSize)},
		),
	}
}

func (c *RangeCheck8Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
