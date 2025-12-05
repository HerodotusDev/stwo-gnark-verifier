package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	BlakeRoundSigmaTraceColumns       = 1
	BlakeRoundSigmaInteractionColumns = 4
)

var BlakeRoundSigmaLogSize = frontend.Variable(4)

type BlakeRoundSigmaClaim struct {
	LogSize frontend.Variable
}

type BlakeRoundSigmaInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BlakeRoundSigmaComponent struct {
	qm31 *m31.QM31Chip

	lookupElements m31.InteractionElements
	claimedSum     m31.QM31
	columnSizeInv  m31.QM31
	vanishEvalInv  m31.QM31
}

func NewBlakeRoundSigma(
	api frontend.API,
	qm31 *m31.QM31Chip,
	lookup m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim BlakeRoundSigmaClaim,
	interactionClaim BlakeRoundSigmaInteractionClaim,
) BlakeRoundSigmaComponent {

	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return BlakeRoundSigmaComponent{
		qm31:           qm31,
		lookupElements: lookup,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  columnSizeInv,
		vanishEvalInv:  vanishEvalInv,
	}
}

func (c BlakeRoundSigmaComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 { // FORMAT
	traceSampledValues, interactionSampledValues := traces.Take(BlakeRoundSigmaTraceColumns, BlakeRoundSigmaInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	values := make([]m31.QM31, 1+16)
	values[0] = traces.Get(NewPreprocessedColumnSeq(BlakeRoundSigmaLogSize))
	for i := 0; i < 16; i++ {
		values[i+1] = traces.Get(NewPreprocessedColumnBlakeSigma(uints.NewU32(uint32(i))))
	}

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	enabler := traceSampledValues.Get(0)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	curr := interactionSampledValues.Partial(c.qm31, 0, 1)
	prev := interactionSampledValues.Partial(c.qm31, 0, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	diff := c.qm31.Sub(curr, prev)

	lookupSum, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}
	claimedAdjustment := c.qm31.Mul(c.claimedSum, c.columnSizeInv)
	g0Inner := c.qm31.Add(diff, claimedAdjustment)
	g0LookupProduct := c.qm31.Mul(g0Inner, lookupSum)
	g0Total := c.qm31.Add(g0LookupProduct, enabler)
	constraint := c.qm31.Mul(g0Total, c.vanishEvalInv)

	sum = c.qm31.Add(c.qm31.Mul(sum, randomCoeff), constraint)
	return sum
}
