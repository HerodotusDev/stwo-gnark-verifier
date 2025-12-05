package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	pedersenPointsTableColumns            = 56
	PedersenPointsTableTraceColumns       = 1
	PedersenPointsTableInteractionColumns = 4
)

var PedersenPointsTableLogSize = 23

type PedersenPointsTableClaim struct {
	LogSize frontend.Variable
}

type PedersenPointsTableInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PedersenPointsTableComponent struct {
	qm31 *m31.QM31Chip

	lookupElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31

	seqColumn    PreprocessedColumn
	pointColumns []PreprocessedColumn
}

func NewPedersenPointsTable(
	api frontend.API,
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	interactionClaim PedersenPointsTableInteractionClaim,
) PedersenPointsTableComponent {
	columnSize := computeColumnSize(api, PedersenPointsTableLogSize)

	pointColumns := make([]PreprocessedColumn, pedersenPointsTableColumns)
	for i := 0; i < pedersenPointsTableColumns; i++ {
		pointColumns[i] = NewPreprocessedColumnPedersenPoints(frontend.Variable(i))
	}

	return PedersenPointsTableComponent{
		qm31:           qm31,
		lookupElements: lookupElements,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  qm31.Inverse(columnSize),
		vanishEvalInv:  vanishEvalInv,
		seqColumn:      NewPreprocessedColumnSeq(PedersenPointsTableLogSize),
		pointColumns:   pointColumns,
	}
}

func (c PedersenPointsTableComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(PedersenPointsTableTraceColumns, PedersenPointsTableInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seq := traces.Get(c.seqColumn)

	values := make([]m31.QM31, 1+len(c.pointColumns))
	values[0] = seq
	for i, column := range c.pointColumns {
		values[i+1] = traces.Get(column)
	}

	tableSum, err := c.qm31.Combine(c.lookupElements, values)
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

	constraint := c.qm31.Mul(diff, tableSum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)

	return accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
}
