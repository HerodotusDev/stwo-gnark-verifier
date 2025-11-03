package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheck19InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck19LogSize = 19

type RangeCheck19Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck19(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck19InteractionClaim,
) *RangeCheck19Component {
	return &RangeCheck19Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck19LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck19LogSize)},
		),
	}
}

func (c *RangeCheck19Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
