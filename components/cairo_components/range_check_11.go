package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck11Claim struct {
	LogSize frontend.Variable
}

var RangeCheck11LogSize = 11

type RangeCheck11InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck11Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck11(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck11InteractionClaim,
) RangeCheck11Component {
	return RangeCheck11Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck11LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(api, RangeCheck11LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck11Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
