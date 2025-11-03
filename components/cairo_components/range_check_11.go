package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const rangeCheck11LogSize = 11

type RangeCheck11InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck11Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck11(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck11InteractionClaim,
) *RangeCheck11Component {
	return &RangeCheck11Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck11LogSize),
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck11LogSize)},
		),
	}
}

func (c *RangeCheck11Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
