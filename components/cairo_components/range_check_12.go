package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck12Claim struct {
	LogSize frontend.Variable
}

var RangeCheck12LogSize = frontend.Variable(12)

type RangeCheck12InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheck12Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck12(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck12InteractionClaim,
) RangeCheck12Component {
	return RangeCheck12Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck12LogSize,
			[]PreprocessedColumn{NewPreprocessedColumnSeq(RangeCheck12LogSize)},
			vanishEvalInv,
		),
	}
}

func (c RangeCheck12Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
