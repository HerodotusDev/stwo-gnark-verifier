package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck44Claim struct {
	LogSize frontend.Variable
}

type RangeCheck44InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck44LogSize = 8

type RangeCheck44Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck44(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck44InteractionClaim,
) RangeCheck44Component {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(4),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck2(values, frontend.Variable(1)),
	}

	return RangeCheck44Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck44LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck44Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
