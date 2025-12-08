package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck18Claim struct {
	LogSize frontend.Variable
}

type RangeCheck18InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck18LogSize = 18

type RangeCheck18Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck18(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck18InteractionClaim,
) RangeCheck18Component {
	return RangeCheck18Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck18LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(api, RangeCheck18LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck18Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
