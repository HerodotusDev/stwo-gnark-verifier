package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const rangeCheck12LogSize = 12

// +---------------------------------------+
// | Range Check 12 Interaction Claim Data |
// +---------------------------------------+
type RangeCheck12InteractionClaim struct {
	ClaimedSum m31.QM31
}

// +-----------------------------------------+
// | Range Check 12 Component Implementation |
// +-----------------------------------------+
type RangeCheck12Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck12(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck12InteractionClaim,
) *RangeCheck12Component {
	return &RangeCheck12Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck12LogSize,
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck12LogSize)},
		),
	}
}

func (c *RangeCheck12Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
