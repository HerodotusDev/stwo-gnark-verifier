package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type RangeCheck3663Claim struct {
	LogSize frontend.Variable
}

type RangeCheck3663InteractionClaim struct {
	ClaimedSum m31.QM31
}

var RangeCheck3663LogSize = frontend.Variable(18)

type RangeCheck3663Component struct {
	inner lookupConstraintComponent
}

func NewRangeCheck3663(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck3663InteractionClaim,
) RangeCheck3663Component {
	values := []frontend.Variable{
		frontend.Variable(3),
		frontend.Variable(6),
		frontend.Variable(6),
		frontend.Variable(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(0)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(1)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(2)),
		NewPreprocessedColumnRangeCheck4(values, frontend.Variable(3)),
	}

	return RangeCheck3663Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			RangeCheck3663LogSize,
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c RangeCheck3663Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
