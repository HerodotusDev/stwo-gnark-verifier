package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	blakeRoundSigmaLogSize            = 4
	blakeRoundSigmaTraceColumns       = 1
	blakeRoundSigmaInteractionColumns = 4
)

type BlakeRoundSigmaClaim struct{}

type BlakeRoundSigmaInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BlakeRoundSigmaComponent struct {
	qm31 *m31.QM31Chip

	lookupElements m31.InteractionElements
	claimedSum     m31.QM31
	columnSizeInv  m31.QM31
	vanishEvalInv  m31.QM31
	preprocessed   []PreprocessedColumn
}

func NewBlakeRoundSigma(
	qm31 *m31.QM31Chip,
	lookup m31.InteractionElements,
	claim BlakeRoundSigmaClaim,
	interactionClaim BlakeRoundSigmaInteractionClaim,
) *BlakeRoundSigmaComponent {
	preprocessed := make([]PreprocessedColumn, 1+16)
	preprocessed[0] = sequencePreprocessedColumn(blakeRoundSigmaLogSize)
	for i := 0; i < 16; i++ {
		preprocessed[i+1] = NewPreprocessedColumnBlakeSigma(uints.NewU8(uint8(i)))
	}

	columnSize := m31.NewM31Unchecked(uint32(1) << blakeRoundSigmaLogSize)
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(columnSize))

	return &BlakeRoundSigmaComponent{
		qm31:           qm31,
		lookupElements: lookup,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  columnSizeInv,
		vanishEvalInv:  qm31.One(), // TODO: wire actual vanishing polynomial evaluation.
		preprocessed:   preprocessed,
	}
}

func (c *BlakeRoundSigmaComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(traceSampledValues) != blakeRoundSigmaTraceColumns {
		panic("blake_round_sigma expects 1 trace column")
	}
	if len(interactionSampledValues) != blakeRoundSigmaInteractionColumns {
		panic("blake_round_sigma expects 4 interaction columns")
	}

	values := make([]m31.QM31, len(c.preprocessed))
	for i, column := range c.preprocessed {
		values[i] = preprocessedSampledValues.Get(column)
	}

	lookupSum, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	enablerColumn := traceSampledValues[0]
	if len(enablerColumn) == 0 {
		panic("blake_round_sigma enabler column empty")
	}
	enabler := enablerColumn[0]

	tr0 := interactionSampledValues[0]
	tr1 := interactionSampledValues[1]
	tr2 := interactionSampledValues[2]
	tr3 := interactionSampledValues[3]

	if len(tr0) < 2 || len(tr1) < 2 || len(tr2) < 2 || len(tr3) < 2 {
		panic("blake_round_sigma interaction columns must have at least two samples")
	}

	curr := c.qm31.FromPartialEvals(tr0[1], tr1[1], tr2[1], tr3[1])
	prev := c.qm31.FromPartialEvals(tr0[0], tr1[0], tr2[0], tr3[0])
	diff := c.qm31.Sub(curr, prev)

	claimedAdjustment := c.qm31.Mul(c.claimedSum, c.columnSizeInv)
	g0Inner := c.qm31.Add(diff, claimedAdjustment)
	g0LookupProduct := c.qm31.Mul(g0Inner, lookupSum)
	g0Total := c.qm31.Add(g0LookupProduct, enabler)
	constraint := c.qm31.Mul(g0Total, c.vanishEvalInv)

	sum = c.qm31.Add(c.qm31.Mul(sum, randomCoeff), constraint)
	return sum
}
