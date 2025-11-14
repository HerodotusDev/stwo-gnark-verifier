package cairo_components

import (
    "github.com/HerodotusDev/stwo-gnark-verifier/m31"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/math/uints"
)

type RangeCheck9_9InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck9_9LogSize = 18

type RangeCheck9_9Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck9_9(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck9_9InteractionClaim,
) *RangeCheck9_9Component {
	values := []uints.U8{
		uints.NewU8(9),
		uints.NewU8(9),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)),
	}

	return &RangeCheck9_9Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck9_9LogSize),
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck9_9Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
