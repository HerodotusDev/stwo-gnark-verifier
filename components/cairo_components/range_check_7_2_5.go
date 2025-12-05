package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck725Claim struct {
	LogSize frontend.Variable
}

type RangeCheck725InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck725LogSize = 14

type RangeCheck725Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck725(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck725InteractionClaim,
) RangeCheck725Component {
	values := []frontend.Variable{
		frontend.Variable(7),
		frontend.Variable(2),
		frontend.Variable(5),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck3(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck3(values, frontend.Variable(1)),
		NewPreprocessedColumnRangeCheck3(values, frontend.Variable(2)),
	}

	return RangeCheck725Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck725LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck725Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
