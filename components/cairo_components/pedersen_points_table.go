package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	pedersenPointsTableLogSize = uint32(23)
	pedersenPointsTableColumns = 56
)

type PedersenPointsTableClaim struct{}

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
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	interactionClaim PedersenPointsTableInteractionClaim,
) *PedersenPointsTableComponent {
	columnSize := uint32(1) << pedersenPointsTableLogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	pointColumns := make([]PreprocessedColumn, pedersenPointsTableColumns)
	for i := 0; i < pedersenPointsTableColumns; i++ {
		pointColumns[i] = NewPreprocessedColumnPedersenPoints(uints.NewU8(uint8(i)))
	}

	return &PedersenPointsTableComponent{
		qm31:           qm31,
		lookupElements: lookupElements,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  qm31.Inverse(columnSizeQM),
		vanishEvalInv:  qm31.One(),
		seqColumn:      NewPreprocessedColumnSeq(uints.NewU8(uint8(pedersenPointsTableLogSize))),
		pointColumns:   pointColumns,
	}
}

func (c *PedersenPointsTableComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(1, 4)

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

	enabler := traceSampledValues[0][0]

	curr := c.qm31.FromPartialEvals(
		interactionSampledValues[0][1],
		interactionSampledValues[1][1],
		interactionSampledValues[2][1],
		interactionSampledValues[3][1],
	)
	prev := c.qm31.FromPartialEvals(
		interactionSampledValues[0][0],
		interactionSampledValues[1][0],
		interactionSampledValues[2][0],
		interactionSampledValues[3][0],
	)

	diff := c.qm31.Sub(curr, prev)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint := c.qm31.Mul(diff, tableSum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)

	return accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
}
