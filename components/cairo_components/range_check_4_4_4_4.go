package cairo_components

import (
    "github.com/HerodotusDev/stwo-gnark-verifier/m31"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/math/uints"
)

type RangeCheck4_4_4_4InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck4_4_4_4LogSize = 16

type RangeCheck4_4_4_4Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck4_4_4_4(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck4_4_4_4InteractionClaim,
) *RangeCheck4_4_4_4Component {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3)),
	}

	return &RangeCheck4_4_4_4Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck4_4_4_4LogSize),
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck4_4_4_4Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
