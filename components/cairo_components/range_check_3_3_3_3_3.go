package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck3_3_3_3_3InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck3_3_3_3_3LogSize = 15

type RangeCheck3_3_3_3_3Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck3_3_3_3_3(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck3_3_3_3_3InteractionClaim,
) *RangeCheck3_3_3_3_3Component {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck5(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck5(values, uints.NewU8(1)),
		NewPreprocessedColumnRangeCheck5(values, uints.NewU8(2)),
		NewPreprocessedColumnRangeCheck5(values, uints.NewU8(3)),
		NewPreprocessedColumnRangeCheck5(values, uints.NewU8(4)),
	}

	return &RangeCheck3_3_3_3_3Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck3_3_3_3_3LogSize,
			preprocessed,
		),
	}
}

func (c *RangeCheck3_3_3_3_3Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
