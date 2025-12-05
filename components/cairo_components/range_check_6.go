package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck6Claim struct {
	LogSize frontend.Variable
}

type RangeCheck6InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck6LogSize = 6

type RangeCheck6Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck6(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck6InteractionClaim,
) RangeCheck6Component {
	return RangeCheck6Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck6LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(RangeCheck6LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck6Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
