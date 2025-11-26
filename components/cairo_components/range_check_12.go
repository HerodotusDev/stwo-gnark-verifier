package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck12Claim struct{}

const rangeCheck12LogSize = 12

type RangeCheck12InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck12Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck12(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck12InteractionClaim,
) *RangeCheck12Component {
	return &RangeCheck12Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck12LogSize),
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck12LogSize)},
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck12Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
