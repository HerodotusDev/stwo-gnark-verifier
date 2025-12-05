package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck19Claim struct {
	LogSize frontend.Variable
}

type RangeCheck19InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck19LogSize = 19

type RangeCheck19Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck19(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck19InteractionClaim,
) RangeCheck19Component {
	return RangeCheck19Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck19LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(RangeCheck19LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck19Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
