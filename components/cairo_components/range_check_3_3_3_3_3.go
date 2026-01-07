package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck33333Claim struct {
	LogSize frontend.Variable
}

type RangeCheck33333InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck33333LogSize = 15

type RangeCheck33333Component struct {
	api   frontend.API
	inner lookupConstraintComponent
}

func NewRangeCheck33333(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck33333InteractionClaim,
) RangeCheck33333Component {
	values := []frontend.Variable{
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
		frontend.Variable(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck5(api, values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck5(api, values, frontend.Variable(1)),
		NewPreprocessedColumnRangeCheck5(api, values, frontend.Variable(2)),
		NewPreprocessedColumnRangeCheck5(api, values, frontend.Variable(3)),
		NewPreprocessedColumnRangeCheck5(api, values, frontend.Variable(4)),
	}

	return RangeCheck33333Component{
		api: api,
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck33333LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck33333Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
