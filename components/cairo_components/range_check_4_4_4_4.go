package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck4444Claim struct {
	LogSize frontend.Variable
}

type RangeCheck4444InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck4444LogSize = 16

type RangeCheck4444Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck4444(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck4444InteractionClaim,
) RangeCheck4444Component {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
		frontend.Variable(4),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(1)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(2)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(3)),
	}

	return RangeCheck4444Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck4444LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck4444Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
