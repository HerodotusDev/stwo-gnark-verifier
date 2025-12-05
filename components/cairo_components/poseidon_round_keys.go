package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	poseidonRoundKeysColumns            = 30
	PoseidonRoundKeysTraceColumns       = 1
	PoseidonRoundKeysInteractionColumns = 4
)

var PoseidonRoundKeysLogSize = frontend.Variable(6)

type PoseidonRoundKeysClaim struct {
	LogSize frontend.Variable
}

type PoseidonRoundKeysInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PoseidonRoundKeysComponent struct {
	qm31 *m31.QM31Chip

	lookupElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31

	seqColumn  PreprocessedColumn
	keyColumns []PreprocessedColumn
}

func NewPoseidonRoundKeys(
	api frontend.API,
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim PoseidonRoundKeysInteractionClaim,
) PoseidonRoundKeysComponent {
	columnSize := computeColumnSize(api, PoseidonRoundKeysLogSize)

	keyColumns := make([]PreprocessedColumn, poseidonRoundKeysColumns)
	for i := 0; i < poseidonRoundKeysColumns; i++ {
		keyColumns[i] = NewPreprocessedColumnPoseidonRoundKeys(frontend.Variable(i))
	}

	return PoseidonRoundKeysComponent{
		qm31:           qm31,
		lookupElements: lookupElements,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  qm31.Inverse(columnSize),
		vanishEvalInv:  vanishEvalInv,
		seqColumn:      NewPreprocessedColumnSeq(PoseidonRoundKeysLogSize),
		keyColumns:     keyColumns,
	}
}

func (c PoseidonRoundKeysComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(PoseidonRoundKeysTraceColumns, PoseidonRoundKeysInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seq := traces.Get(c.seqColumn)

	values := make([]m31.QM31, 1+len(c.keyColumns))
	values[0] = seq
	for i, column := range c.keyColumns {
		values[i+1] = traces.Get(column)
	}

	lookupSum, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
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
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint := c.qm31.Mul(diff, lookupSum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)

	return accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
}
