package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

type RangeCheck4_3InteractionClaim struct {
	ClaimedSum m31.QM31
}

const rangeCheck4_3LogSize = 7

type RangeCheck4_3Component struct {
	inner *lookupConstraintComponent
}

func NewRangeCheck4_3(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim RangeCheck4_3InteractionClaim,
) *RangeCheck4_3Component {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(3),
	}
	preprocessed := []PreprocessedColumn{
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0)),
		NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1)),
	}

	return &RangeCheck4_3Component{
		inner: newLookupConstraintComponent(
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			rangeCheck4_3LogSize,
			preprocessed,
		),
	}
}

func (c *RangeCheck4_3Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}
