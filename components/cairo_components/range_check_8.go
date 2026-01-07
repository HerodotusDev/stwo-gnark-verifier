package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck8Claim struct{}

type RangeCheck8InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck8LogSize = 8

type RangeCheck8Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck8(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck8InteractionClaim,
) *RangeCheck8Component {
	return &RangeCheck8Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck8LogSize),
			[]PreprocessedColumn{sequencePreprocessedColumn(rangeCheck8LogSize)},
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck8Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
