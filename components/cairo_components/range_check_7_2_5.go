package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck7_2_5Claim struct{}

type RangeCheck7_2_5InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck7_2_5LogSize = 14

type RangeCheck7_2_5Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck7_2_5(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim RangeCheck7_2_5InteractionClaim,
) *RangeCheck7_2_5Component {
	values := []uints.U8{
		uints.NewU8(7),
		uints.NewU8(2),
		uints.NewU8(5),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck3(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck3(values, uints.NewU8(1)),
		NewPreprocessedColumnRangeCheck3(values, uints.NewU8(2)),
	}

	return &RangeCheck7_2_5Component{
		inner: newLookupConstraintComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			uints.NewU8(rangeCheck7_2_5LogSize),
			preprocessed,
			vanishEvalInv,
		),
	}
}

func (c *RangeCheck7_2_5Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
