package cairo_components

import (
    "github.com/HerodotusDev/stwo-gnark-verifier/m31"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/math/uints"
)

type RangeCheck5_4InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck5_4LogSize = 9

type RangeCheck5_4Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck5_4(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck5_4InteractionClaim,
) *RangeCheck5_4Component {
    values := []uints.U8{
        uints.NewU8(5),
        uints.NewU8(4),
    }
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)),
	}

	return &RangeCheck5_4Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck5_4LogSize),
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck5_4Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
