package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck19Claim struct{}

type RangeCheck19InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck19LogSize = 19

type RangeCheck19Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck19(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck19InteractionClaim,
) *RangeCheck19Component {
	return &RangeCheck19Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck19LogSize),
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck19LogSize)},
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck19Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
