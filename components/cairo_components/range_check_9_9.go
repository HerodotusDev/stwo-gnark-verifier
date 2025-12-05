package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck99Claim struct {
	LogSize frontend.Variable
}

type RangeCheck99InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck99LogSize = 18

type RangeCheck99Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck99(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck99InteractionClaim,
) RangeCheck99Component {
	values := []frontend.Variable{
		frontend.Variable(9),
		frontend.Variable(9),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)),
	}

	return RangeCheck99Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck99LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck99Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
