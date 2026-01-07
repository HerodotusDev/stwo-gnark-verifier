package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck43Claim struct {
	LogSize frontend.Variable
}

type RangeCheck43InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck43LogSize = 7

type RangeCheck43Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck43(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck43InteractionClaim,
) RangeCheck43Component {
	values := []frontend.Variable{
		frontend.Variable(4),
		frontend.Variable(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(api, values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck2(api, values, frontend.Variable(1)),
	}

	return RangeCheck43Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck43LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck43Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
