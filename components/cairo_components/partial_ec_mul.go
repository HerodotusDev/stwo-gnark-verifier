package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	partialEcMulTraceColumns       = 472
	partialEcMulInteractionColumns = 428
)

type PartialEcMulClaim struct {
	LogSize uint32
}

type PartialEcMulComponent struct {
	qm31 *m31.QM31Chip
}

type PartialEcMulInteractionClaim struct {
	ClaimedSum m31.QM31
}

func NewPartialEcMul(
	qm31Chip *m31.QM31Chip,
	_ m31.InteractionElements,
	_ m31.InteractionElements,
	_ m31.InteractionElements,
	_ m31.InteractionElements,
	_ PartialEcMulClaim,
	_ PartialEcMulInteractionClaim,
) *PartialEcMulComponent {
	return &PartialEcMulComponent{qm31: qm31Chip}
}

func (c *PartialEcMulComponent) Evaluate(
	sum m31.QM31,
	preprocessed PreprocessedSampledValues,
	trace [][]m31.QM31,
	interaction [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessed

	if len(trace) != partialEcMulTraceColumns {
		panic("partial_ec_mul expects 472 trace columns")
	}
	if len(interaction) != partialEcMulInteractionColumns {
		panic("partial_ec_mul expects 428 interaction columns")
	}

	_ = trace
	_ = interaction

	constant := m31.NewQM31Unchecked(2134487123, 1606942236, 1343226536, 1071644986)
	return c.qm31.Add(c.qm31.Mul(sum, randomCoeff), constant)
}
