package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck3_6_6_3Claim struct{}

type RangeCheck3_6_6_3InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck3_6_6_3LogSize = 18

type RangeCheck3_6_6_3Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck3_6_6_3(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck3_6_6_3InteractionClaim,
) *RangeCheck3_6_6_3Component {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(6),
		uints.NewU8(6),
		uints.NewU8(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2)),
		NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3)),
	}

	return &RangeCheck3_6_6_3Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck3_6_6_3LogSize),
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck3_6_6_3Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
