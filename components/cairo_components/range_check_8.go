package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck8Claim struct {
	LogSize frontend.Variable
}

type RangeCheck8InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck8LogSize = frontend.Variable(8)

type RangeCheck8Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck8(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck8InteractionClaim,
) RangeCheck8Component {
	return RangeCheck8Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck8LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(RangeCheck8LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck8Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
