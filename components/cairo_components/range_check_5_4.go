package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck54Claim struct {
	LogSize frontend.Variable
}

type RangeCheck54InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck54LogSize = frontend.Variable(9)

type RangeCheck54Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck54(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck54InteractionClaim,
) RangeCheck54Component {
	values := []frontend.Variable{
		frontend.Variable(5),
		frontend.Variable(4),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)),
	}

	return RangeCheck54Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck54LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck54Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
